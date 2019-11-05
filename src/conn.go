package src

import (
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type mConn struct {
	d         *([]*client)
	c         net.Conn
	b         []byte
	handshake chan (interface{})
	mutex     sync.Mutex
	cmutex    sync.Mutex
	config    config
	log       zerolog.Logger
}

func (s *mConn) Read(b []byte) (n int, err error) {
	<-s.handshake
	if len(s.b) > 0 {
		n := copy(b, s.b)
		s.b = s.b[n:]
		return n, nil
	}
	return s.c.Read(b)
}

func (s *mConn) Write(b []byte) (n int, err error) {
	<-s.handshake
	return s.c.Write(b)
}

func (s *mConn) Close() error {
	<-s.handshake
	return s.c.Close()
}

func (s *mConn) LocalAddr() net.Addr {
	<-s.handshake
	return s.c.LocalAddr()
}

func (s *mConn) RemoteAddr() net.Addr {
	<-s.handshake
	return s.c.RemoteAddr()
}

func (s *mConn) SetDeadline(t time.Time) error {
	<-s.handshake
	return s.c.SetDeadline(t)
}

func (s *mConn) SetReadDeadline(t time.Time) error {
	<-s.handshake
	return s.c.SetReadDeadline(t)
}

func (s *mConn) SetWriteDeadline(t time.Time) error {
	<-s.handshake
	return s.c.SetWriteDeadline(t)
}

func (s *mConn) Dail(net, address string, buf []byte) (net.Conn, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.log = s.config.logger.With().Str("To", address).Logger()
	s.handshake = make(chan interface{})
	for _, c := range *s.d {
		go s.dail(net, address, buf, c)
	}
	return s, nil
}

func (s *mConn) dail(net, address string, buf []byte, c *client) error {
	log := s.log.With().Str("From", c.address).Logger()
	conn, err := c.dailer.Dial(net, address)
	if err != nil {
		log.Debug().Err(err).Send()
		return err
	}
	select {
	case <-s.handshake:
		log.Debug().Timestamp().Msg("exit")
		conn.Close()
		return nil
	default:
	}
	log.Debug().Timestamp().Msg("dail")
	conn.Write(buf)
	select {
	case <-s.handshake:
		log.Debug().Timestamp().Msg("exit")
		conn.Close()
		return nil
	default:
	}
	log.Debug().Timestamp().Msg("write")
	b := make([]byte, 10240)
	n, err := conn.Read(b)
	b = b[:n]
	log.Debug().Timestamp().Msg("read")
	s.cmutex.Lock()
	defer s.cmutex.Unlock()
	select {
	case <-s.handshake:
		log.Debug().Timestamp().Msg("exit")
		conn.Close()
		return nil
	default:
		log.Debug().Timestamp().Msg("set")
		s.b = b
		s.c = conn
		close(s.handshake)
	}
	return nil
}
