package src

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"

	"golang.org/x/net/proxy"

	"github.com/armon/go-socks5"
	"github.com/rs/zerolog"
)

const (
	socks5Version   = uint8(5)
	NoAuth          = uint8(0)
	noAcceptable    = uint8(255)
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
	ipv4Address     = uint8(1)
	fqdnAddress     = uint8(3)
	ipv6Address     = uint8(4)
)
const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

var (
	UserAuthFailed       = fmt.Errorf("User authentication failed")
	NoSupportedAuth      = fmt.Errorf("No supported authentication mechanism")
	unrecognizedAddrType = fmt.Errorf("Unrecognized address type")
)

type server struct {
	config
	authMethods map[uint8]socks5.Authenticator
	clients     []*client
	log         zerolog.Logger
}

func (s *server) init() *server {
	AuthMethods := []socks5.Authenticator{&socks5.NoAuthAuthenticator{}}
	s.authMethods = make(map[uint8]socks5.Authenticator)
	for _, a := range AuthMethods {
		s.authMethods[a.GetCode()] = a
	}
	s.clients = make([]*client, 0)
	for _, v := range s.Rules {
		u, err := url.Parse(v)
		if err != nil {
			s.log.Fatal().Err(err).Msg("Parse url failed.")
		}
		var c *client
		if u.User != nil {
			p, _ := u.User.Password()
			a := proxy.Auth{u.User.Username(), p}
			c = &client{
				config:  s.config,
				address: u.Host,
				auth:    &a,
			}
		} else {
			c = &client{
				config:  s.config,
				address: u.Host,
			}
		}
		c.init()
		s.clients = append(s.clients, c)
	}
	s.log = s.config.logger.With().Str("module", "handler").Logger()
	return s
}

func (s *server) server() error {
	l, err := net.Listen("tcp", s.Listen)
	if err != nil {
		s.log.Fatal().Err(err).Msg("Listen failed.")
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.serveConn(conn)
	}
}

func readMethods(r io.Reader) ([]byte, error) {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(r, methods, numMethods)
	return methods, err
}

func noAcceptableAuth(conn io.Writer) error {
	conn.Write([]byte{socks5Version, noAcceptable})
	return NoSupportedAuth
}

func (s *server) authenticate(conn io.Writer, bufConn io.Reader) (*socks5.AuthContext, error) {
	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		return nil, fmt.Errorf("Failed to get auth methods: %v", err)
	}

	// Select a usable method
	for _, method := range methods {
		cator, found := s.authMethods[method]
		if found {
			return cator.Authenticate(bufConn, conn)
		}
	}

	// No usable method found
	return nil, noAcceptableAuth(conn)
}
func sendReply(w io.Writer, resp uint8, addr *socks5.AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}
func (s *server) serveConn(conn net.Conn) error {
	defer conn.Close()
	bufConn := bufio.NewReader(conn)

	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		s.log.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return err
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		s.log.Printf("[ERR] socks: %v", err)
		return err
	}

	// Authenticate the connection
	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		err = fmt.Errorf("Failed to authenticate: %v", err)
		s.log.Printf("[ERR] socks: %v", err)
		return err
	}

	request, err := socks5.NewRequest(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}
	request.AuthContext = authContext
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &socks5.AddrSpec{IP: client.IP, Port: client.Port}
	}

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		err = fmt.Errorf("Failed to handle request: %v", err)
		s.log.Printf("[ERR] socks: %v", err)
		return err
	}

	return nil
}

type closeWriter interface {
	CloseWrite() error
}

func pipe(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}

func (s *server) handleRequest(req *socks5.Request, conn net.Conn) error {
	ctx := context.Background()
	// Switch on the command
	switch req.Command {
	case socks5.ConnectCommand:
		return s.handleConnect(ctx, conn, req)
	default:
		if err := sendReply(conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Unsupported command: %v", req.Command)
	}
}

func (s *server) handleConnect(ctx context.Context, conn net.Conn, req *socks5.Request) error {
	//if err := sendReply(conn, successReply, &socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 80}); err != nil {
	if err := sendReply(conn, successReply, req.DestAddr); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	dst := ""
	if req.DestAddr.FQDN != "" {
		dst = fmt.Sprintf("%s:%d", req.DestAddr.FQDN, req.DestAddr.Port)
	} else {
		dst = fmt.Sprintf("%s:%d", req.DestAddr.IP.String(), req.DestAddr.Port)
	}
	s.log.Debug().Str("To", dst).Msg("handle")
	buf := make([]byte, 10240)
	n, err := conn.Read(buf)
	if err != nil {
		s.log.Debug().Str("To", dst).Err(err).Msg("read failed")
	}
	buf = buf[:n]
	c := &mConn{
		config: s.config,
		d:      &s.clients,
	}
	c.Dail("tcp", dst, buf)
	s.log.Debug().Str("To", dst).Msg("dail")
	// Start proxying
	errCh := make(chan error, 2)
	go pipe(c, conn, errCh)
	go pipe(conn, c, errCh)
	s.log.Debug().Str("To", dst).Msg("pipe")
	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			// return from this function closes target (and conn).
			return e
		}
	}
	return nil
}
