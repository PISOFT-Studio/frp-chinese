// frp 客户端服务端实现
package client

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/fatedier/golib/crypto"
	"github.com/fatedier/golib/errors"
	"github.com/fatedier/golib/log"
	"github.com/fatedier/golib/sync"

	"github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport"
)

type Service struct {
	runID         string
	conn          net.Conn
	writer        *msg.MsgWriter
	reader        *msg.MsgReader
	cfg           *config.ClientCommonConf
	eventRecorder sync.EventRecorder
}

func NewService(cfg *config.ClientCommonConf) *Service {
	return &Service{
		cfg:           cfg,
		eventRecorder: sync.NewEventRecorder(),
	}
}

// 启动客户端服务，连接到 frps 并发送 Login 消息
func (svr *Service) Run(ctx context.Context) error {
	var err error
	svr.conn, err = transport.ConnectServerByProxy(ctx, svr.cfg)
	if err != nil {
		return fmt.Errorf("连接服务器失败: %v", err)
	}

	svr.writer = msg.NewMsgWriter(svr.conn)
	svr.reader = msg.NewMsgReader(svr.conn)

	// 生成客户端登录验证信息
	timestamp := time.Now().Unix()
	token := crypto.HmacSign([]byte(svr.cfg.Token), []byte(fmt.Sprintf("%d", timestamp)))
	loginMsg := &msg.Login{
		Version:       svr.cfg.Version,
		Hostname:      svr.cfg.Hostname,
		Os:            svr.cfg.Os,
		Arch:          svr.cfg.Arch,
		User:          svr.cfg.User,
		Timestamp:     timestamp,
		PrivilegeKey:  token,
		RunID:         svr.runID,
		PoolCount:     svr.cfg.PoolCount,
		Metas:         svr.cfg.Metas,
		ClientID:      svr.cfg.ClientID,
		AdminAddr:     svr.cfg.AdminAddr,
		AdminPort:     svr.cfg.AdminPort,
		AdminUser:     svr.cfg.AdminUser,
		AdminPwd:      svr.cfg.AdminPwd,
		UseEncryption: svr.cfg.UseEncryption,
		UseCompression: svr.cfg.UseCompression,
	}

	err = svr.writer.WriteMsg(loginMsg)
	if err != nil {
		return fmt.Errorf("发送登录信息失败: %v", err)
	}
	log.Info("登录信息已发送")

	// 读取登录响应
	resp, err := svr.reader.ReadMsg()
	if err != nil {
		return fmt.Errorf("读取服务器响应失败: %v", err)
	}
	loginResp, ok := resp.(*msg.LoginResp)
	if !ok {
		return fmt.Errorf("服务器返回了无效的登录响应")
	}

	if loginResp.Error != "" {
		return fmt.Errorf("登录失败: %s", loginResp.Error)
	}

	svr.runID = loginResp.RunID
	log.Infof("成功连接服务器，分配的 RunID 为 %s", svr.runID)

	// 后续处理逻辑略
	return nil
}

func (svr *Service) Close() {
	if svr.conn != nil {
		svr.conn.Close()
	}
	log.Info("客户端服务已关闭")
}
