// 版权所有 2017 fatedier, fatedier@gmail.com
//
// 根据 Apache 许可证 2.0 版本授权
// 除非遵守许可证，否则不得使用本文件。
// 可通过以下链接获取许可证副本：
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// 除非适用法律要求或书面同意，软件按“原样”提供，
// 不附带任何明示或暗示的保证或条件。
// 有关具体语言，请参阅许可证。

package client

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/fatedier/frp/client/proxy"
	"github.com/fatedier/frp/client/visitor"
	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/wait"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/pkg/vnet"
)

// SessionContext 表示一次客户端和服务器建立的完整会话上下文
type SessionContext struct {
	Common         *v1.ClientCommonConfig // 客户端公共配置
	RunID          string                 // 从 frps 获取的唯一标识，用于重连时使用
	Conn           net.Conn               // 控制连接，一旦关闭，msgDispatcher 和 Control 会全部退出
	ConnEncrypted  bool                   // 是否加密连接
	AuthSetter     auth.Setter            // 根据选定的认证方式设置身份认证
	Connector      Connector              // 用于创建连接的对象（真实 TCP 或虚拟连接）
	VnetController *vnet.Controller       // 虚拟网络控制器
}

// Control 控制器，管理客户端与服务器之间的主连接及其通信行为
type Control struct {
	ctx             context.Context
	xl              *xlog.Logger
	sessionCtx      *SessionContext
	pm              *proxy.Manager
	vm              *visitor.Manager
	doneCh          chan struct{}
	lastPong        atomic.Value
	msgTransporter  transport.MessageTransporter
	msgDispatcher   *msg.Dispatcher
}

// 创建新的控制器实例
func NewControl(ctx context.Context, sessionCtx *SessionContext) (*Control, error) {
	ctl := &Control{
		ctx:        ctx,
		xl:         xlog.FromContextSafe(ctx),
		sessionCtx: sessionCtx,
		doneCh:     make(chan struct{}),
	}
	ctl.lastPong.Store(time.Now())

	if sessionCtx.ConnEncrypted {
		cryptoRW, err := netpkg.NewCryptoReadWriter(sessionCtx.Conn, []byte(sessionCtx.Common.Auth.Token))
		if err != nil {
			return nil, err
		}
		ctl.msgDispatcher = msg.NewDispatcher(cryptoRW)
	} else {
		ctl.msgDispatcher = msg.NewDispatcher(sessionCtx.Conn)
	}
	ctl.registerMsgHandlers()
	ctl.msgTransporter = transport.NewMessageTransporter(ctl.msgDispatcher.SendChannel())

	ctl.pm = proxy.NewManager(ctl.ctx, sessionCtx.Common, ctl.msgTransporter, sessionCtx.VnetController)
	ctl.vm = visitor.NewManager(ctl.ctx, sessionCtx.RunID, sessionCtx.Common,
		ctl.connectServer, ctl.msgTransporter, sessionCtx.VnetController)
	return ctl, nil
}

// 启动所有代理和访问器
func (ctl *Control) Run(proxyCfgs []v1.ProxyConfigurer, visitorCfgs []v1.VisitorConfigurer) {
	go ctl.worker()

	ctl.pm.UpdateAll(proxyCfgs)
	ctl.vm.UpdateAll(visitorCfgs)
}

// 设置处理工作连接的回调
func (ctl *Control) SetInWorkConnCallback(cb func(*v1.ProxyBaseConfig, net.Conn, *msg.StartWorkConn) bool) {
	ctl.pm.SetInWorkConnCallback(cb)
}

// 处理服务器请求新的工作连接消息
func (ctl *Control) handleReqWorkConn(_ msg.Message) {
	xl := ctl.xl
	workConn, err := ctl.connectServer()
	if err != nil {
		xl.Warnf("创建工作连接失败: %v", err)
		return
	}

	m := &msg.NewWorkConn{RunID: ctl.sessionCtx.RunID}
	if err = ctl.sessionCtx.AuthSetter.SetNewWorkConn(m); err != nil {
		xl.Warnf("工作连接认证失败: %v", err)
		workConn.Close()
		return
	}
	if err = msg.WriteMsg(workConn, m); err != nil {
		xl.Warnf("发送工作连接消息失败: %v", err)
		workConn.Close()
		return
	}

	var startMsg msg.StartWorkConn
	if err = msg.ReadMsgInto(workConn, &startMsg); err != nil {
		xl.Tracef("工作连接在接收 StartWorkConn 前关闭: %v", err)
		workConn.Close()
		return
	}
	if startMsg.Error != "" {
		xl.Errorf("StartWorkConn 返回错误: %s", startMsg.Error)
		workConn.Close()
		return
	}

	// 将工作连接分发给对应的代理
	ctl.pm.HandleWorkConn(startMsg.ProxyName, workConn, &startMsg)
}

// 处理服务器返回的新代理响应
func (ctl *Control) handleNewProxyResp(m msg.Message) {
	xl := ctl.xl
	inMsg := m.(*msg.NewProxyResp)

	err := ctl.pm.StartProxy(inMsg.ProxyName, inMsg.RemoteAddr, inMsg.Error)
	if err != nil {
		xl.Warnf("[%s] 启动失败: %v", inMsg.ProxyName, err)
	} else {
		xl.Infof("[%s] 启动代理成功", inMsg.ProxyName)
	}
}

// 处理穿透打洞响应消息
func (ctl *Control) handleNatHoleResp(m msg.Message) {
	xl := ctl.xl
	inMsg := m.(*msg.NatHoleResp)

	ok := ctl.msgTransporter.DispatchWithType(inMsg, msg.TypeNameNatHoleResp, inMsg.TransactionID)
	if !ok {
		xl.Tracef("NatHoleResp 消息分发失败")
	}
}

// 处理服务器 PONG 消息（心跳响应）
func (ctl *Control) handlePong(m msg.Message) {
	xl := ctl.xl
	inMsg := m.(*msg.Pong)

	if inMsg.Error != "" {
		xl.Errorf("Pong 消息错误: %s", inMsg.Error)
		ctl.closeSession()
		return
	}
	ctl.lastPong.Store(time.Now())
	xl.Debugf("收到服务器心跳响应")
}

// 关闭控制连接
func (ctl *Control) closeSession() {
	ctl.sessionCtx.Conn.Close()
	ctl.sessionCtx.Connector.Close()
}

// 主动关闭控制器
func (ctl *Control) Close() error {
	return ctl.GracefulClose(0)
}

// 优雅关闭控制器，延迟 d 后释放资源
func (ctl *Control) GracefulClose(d time.Duration) error {
	ctl.pm.Close()
	ctl.vm.Close()

	time.Sleep(d)

	ctl.closeSession()
	return nil
}

// 返回一个 channel，当所有资源释放后关闭
func (ctl *Control) Done() <-chan struct{} {
	return ctl.doneCh
}

// 创建一条新的控制连接到服务器
func (ctl *Control) connectServer() (net.Conn, error) {
	return ctl.sessionCtx.Connector.Connect()
}

// 注册所有支持的消息处理器
func (ctl *Control) registerMsgHandlers() {
	ctl.msgDispatcher.RegisterHandler(&msg.ReqWorkConn{}, msg.AsyncHandler(ctl.handleReqWorkConn))
	ctl.msgDispatcher.RegisterHandler(&msg.NewProxyResp{}, ctl.handleNewProxyResp)
	ctl.msgDispatcher.RegisterHandler(&msg.NatHoleResp{}, ctl.handleNatHoleResp)
	ctl.msgDispatcher.RegisterHandler(&msg.Pong{}, ctl.handlePong)
}

// 心跳检测与定时器
func (ctl *Control) heartbeatWorker() {
	xl := ctl.xl

	if ctl.sessionCtx.Common.Transport.HeartbeatInterval > 0 {
		sendHeartBeat := func() (bool, error) {
			xl.Debugf("发送心跳到服务器")
			pingMsg := &msg.Ping{}
			if err := ctl.sessionCtx.AuthSetter.SetPing(pingMsg); err != nil {
				xl.Warnf("心跳认证失败: %v，跳过", err)
				return false, err
			}
			_ = ctl.msgDispatcher.Send(pingMsg)
			return false, nil
		}

		go wait.BackoffUntil(sendHeartBeat,
			wait.NewFastBackoffManager(wait.FastBackoffOptions{
				Duration:           time.Duration(ctl.sessionCtx.Common.Transport.HeartbeatInterval) * time.Second,
				InitDurationIfFail: time.Second,
				Factor:             2.0,
				Jitter:             0.1,
				MaxDuration:        time.Duration(ctl.sessionCtx.Common.Transport.HeartbeatInterval) * time.Second,
			}),
			true, ctl.doneCh,
		)
	}

	// 心跳超时检测
	if ctl.sessionCtx.Common.Transport.HeartbeatInterval > 0 &&
		ctl.sessionCtx.Common.Transport.HeartbeatTimeout > 0 {
		go wait.Until(func() {
			if time.Since(ctl.lastPong.Load().(time.Time)) > time.Duration(ctl.sessionCtx.Common.Transport.HeartbeatTimeout)*time.Second {
				xl.Warnf("心跳超时")
				ctl.closeSession()
				return
			}
		}, time.Second, ctl.doneCh)
	}
}

// 后台运行控制器主逻辑
func (ctl *Control) worker() {
	go ctl.heartbeatWorker()
	go ctl.msgDispatcher.Run()

	<-ctl.msgDispatcher.Done()
	ctl.closeSession()

	ctl.pm.Close()
	ctl.vm.Close()
	close(ctl.doneCh)
}

// 更新所有代理与访客配置
func (ctl *Control) UpdateAllConfigurer(proxyCfgs []v1.ProxyConfigurer, visitorCfgs []v1.VisitorConfigurer) error {
	ctl.vm.UpdateAll(visitorCfgs)
	ctl.pm.UpdateAll(proxyCfgs)
	return nil
}
