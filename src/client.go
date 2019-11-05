package src

import (
	"net"
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
)

type rc interface {
	connect() (net.Conn, error)
}

type client struct {
	config
	address string
	auth    *proxy.Auth
	online  bool
	mutex   sync.Mutex
	dailer  proxy.Dialer
	log     zerolog.Logger
}

func (s *client) init() *client {
	var err error
	s.log = s.config.logger.With().Str("client", s.address).Logger()
	s.dailer, err = proxy.SOCKS5("tcp", s.address, s.auth, nil)
	if err != nil {
		s.log.Warn().Str("option", "create dailer").Err(err).Send()
		s.online = false
	}
	return s
}
