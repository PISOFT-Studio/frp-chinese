// 版权所有 2023 frp 项目作者
//
// 根据 Apache License, Version 2.0 许可证授权
// 除非符合许可证规定，否则您不得使用此文件
// 获取许可证副本请访问：
//     http://www.apache.org/licenses/LICENSE-2.0
//
// 本文件按“原样”提供，不提供任何明示或暗示的担保
// 详情请参考许可证内容

package client

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	libnet "github.com/fatedier/golib/net"
	fmux "github.com/hashicorp/yamux"
	quic "github.com/quic-go/quic-go"
	"github.com/samber/lo"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/transport"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/xlog"
)

// Connector 是一个用于建立到服务端连接的接口
type Connector interface {
	Open() error          // 打开底层连接
	Connect() (net.Conn, error) // 获取一个逻辑连接
	Close() error         // 关闭连接
}

// defaultConnectorImpl 是 frpc 的默认连接实现
type defaultConnectorImpl struct {
	ctx context.Context
	cfg *v1.ClientCommonConfig

	muxSession *fmux.Session
	quicConn   quic.Connection
	closeOnce  sync.Once
}

// 创建一个默认连接器实例
func NewConnector(ctx context.Context, cfg *v1.ClientCommonConfig) Connector {
	return &defaultConnectorImpl{
		ctx: ctx,
		cfg: cfg,
	}
}

// Open 方法会建立到底层服务端的连接，可能是 TCP 或 QUIC 连接。
// 若启用了 TCP 多路复用（TCPMux），后续可通过 Connect() 获取逻辑连接。
// 若未启用 TCPMux，则每次调用 Connect() 都会新建实际的 TCP 连接。
func (c *defaultConnectorImpl) Open() error {
	xl := xlog.FromContextSafe(c.ctx)

	// 特殊处理：QUIC 协议
	if strings.EqualFold(c.cfg.Transport.Protocol, "quic") {
		var tlsConfig *tls.Config
		var err error
		sn := c.cfg.Transport.TLS.ServerName
		if sn == "" {
			sn = c.cfg.ServerAddr
		}
		if lo.FromPtr(c.cfg.Transport.TLS.Enable) {
			tlsConfig, err = transport.NewClientTLSConfig(
				c.cfg.Transport.TLS.CertFile,
				c.cfg.Transport.TLS.KeyFile,
				c.cfg.Transport.TLS.TrustedCaFile,
				sn)
		} else {
			tlsConfig, err = transport.NewClientTLSConfig("", "", "", sn)
		}
		if err != nil {
			xl.Warnf("构建 TLS 配置失败: %v", err)
			return err
		}
		tlsConfig.NextProtos = []string{"frp"}

		conn, err := quic.DialAddr(
			c.ctx,
			net.JoinHostPort(c.cfg.ServerAddr, strconv.Itoa(c.cfg.ServerPort)),
			tlsConfig, &quic.Config{
				MaxIdleTimeout:     time.Duration(c.cfg.Transport.QUIC.MaxIdleTimeout) * time.Second,
				MaxIncomingStreams: int64(c.cfg.Transport.QUIC.MaxIncomingStreams),
				KeepAlivePeriod:    time.Duration(c.cfg.Transport.QUIC.KeepalivePeriod) * time.Second,
			})
		if err != nil {
			return err
		}
		c.quicConn = conn
		return nil
	}

	// 未启用 TCP 多路复用，直接返回
	if !lo.FromPtr(c.cfg.Transport.TCPMux) {
		return nil
	}

	// 建立实际连接
	conn, err := c.realConnect()
	if err != nil {
		return err
	}

	// 创建 yamux 多路复用会话
	fmuxCfg := fmux.DefaultConfig()
	fmuxCfg.KeepAliveInterval = time.Duration(c.cfg.Transport.TCPMuxKeepaliveInterval) * time.Second
	fmuxCfg.LogOutput = io.Discard
	fmuxCfg.MaxStreamWindowSize = 6 * 1024 * 1024
	session, err := fmux.Client(conn, fmuxCfg)
	if err != nil {
		return err
	}
	c.muxSession = session
	return nil
}

// Connect 从已建立的底层连接中返回一个逻辑流连接。
// 如果未启用多路复用，则会建立一个新的 TCP 实际连接。
func (c *defaultConnectorImpl) Connect() (net.Conn, error) {
	if c.quicConn != nil {
		stream, err := c.quicConn.OpenStreamSync(context.Background())
		if err != nil {
			return nil, err
		}
		return netpkg.QuicStreamToNetConn(stream, c.quicConn), nil
	} else if c.muxSession != nil {
		stream, err := c.muxSession.OpenStream()
		if err != nil {
			return nil, err
		}
		return stream, nil
	}

	return c.realConnect()
}

// 建立真实 TCP 连接（无复用）
func (c *defaultConnectorImpl) realConnect() (net.Conn, error) {
	xl := xlog.FromContextSafe(c.ctx)
	var tlsConfig *tls.Config
	var err error
	tlsEnable := lo.FromPtr(c.cfg.Transport.TLS.Enable)
	if c.cfg.Transport.Protocol == "wss" {
		tlsEnable = true
	}
	if tlsEnable {
		sn := c.cfg.Transport.TLS.ServerName
		if sn == "" {
			sn = c.cfg.ServerAddr
		}

		tlsConfig, err = transport.NewClientTLSConfig(
			c.cfg.Transport.TLS.CertFile,
			c.cfg.Transport.TLS.KeyFile,
			c.cfg.Transport.TLS.TrustedCaFile,
			sn)
		if err != nil {
			xl.Warnf("构建 TLS 配置失败: %v", err)
			return nil, err
		}
	}

	// 解析代理地址
	proxyType, addr, auth, err := libnet.ParseProxyURL(c.cfg.Transport.ProxyURL)
	if err != nil {
		xl.Errorf("解析代理地址失败")
		return nil, err
	}

	dialOptions := []libnet.DialOption{}
	protocol := c.cfg.Transport.Protocol

	switch protocol {
	case "websocket":
		protocol = "tcp"
		dialOptions = append(dialOptions, libnet.WithAfterHook(libnet.AfterHook{Hook: netpkg.DialHookWebsocket(protocol, "")}))
		dialOptions = append(dialOptions, libnet.WithAfterHook(libnet.AfterHook{
			Hook: netpkg.DialHookCustomTLSHeadByte(tlsConfig != nil, lo.FromPtr(c.cfg.Transport.TLS.DisableCustomTLSFirstByte)),
		}))
		dialOptions = append(dialOptions, libnet.WithTLSConfig(tlsConfig))
	case "wss":
		protocol = "tcp"
		dialOptions = append(dialOptions, libnet.WithTLSConfigAndPriority(100, tlsConfig))
		dialOptions = append(dialOptions, libnet.WithAfterHook(libnet.AfterHook{
			Hook:    netpkg.DialHookWebsocket(protocol, tlsConfig.ServerName),
			Priority: 110,
		}))
	default:
		dialOptions = append(dialOptions, libnet.WithAfterHook(libnet.AfterHook{
			Hook: netpkg.DialHookCustomTLSHeadByte(tlsConfig != nil, lo.FromPtr(c.cfg.Transport.TLS.DisableCustomTLSFirstByte)),
		}))
		dialOptions = append(dialOptions, libnet.WithTLSConfig(tlsConfig))
	}

	if c.cfg.Transport.ConnectServerLocalIP != "" {
		dialOptions = append(dialOptions, libnet.WithLocalAddr(c.cfg.Transport.ConnectServerLocalIP))
	}

	dialOptions = append(dialOptions,
		libnet.WithProtocol(protocol),
		libnet.WithTimeout(time.Duration(c.cfg.Transport.DialServerTimeout)*time.Second),
		libnet.WithKeepAlive(time.Duration(c.cfg.Transport.DialServerKeepAlive)*time.Second),
		libnet.WithProxy(proxyType, addr),
		libnet.WithProxyAuth(auth),
	)

	conn, err := libnet.DialContext(
		c.ctx,
		net.JoinHostPort(c.cfg.ServerAddr, strconv.Itoa(c.cfg.ServerPort)),
		dialOptions...,
	)
	return conn, err
}

// 关闭底层连接，确保只关闭一次
func (c *defaultConnectorImpl) Close() error {
	c.closeOnce.Do(func() {
		if c.quicConn != nil {
			_ = c.quicConn.CloseWithError(0, "")
		}
		if c.muxSession != nil {
			_ = c.muxSession.Close()
		}
	})
	return nil
}
