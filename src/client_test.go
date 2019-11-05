package src

import (
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestClientInit(t *testing.T) {
	c := (&client{
		address: "10.2.255.1:8099",
		log:     zerolog.New(os.Stdout),
	}).init()
	t.Log(time.Now().String())
	conn, err := c.dailer.Dial("tcp", "www.google.com:80")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log(time.Now().String())
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	t.Log(time.Now().String())
	t.Log(n, err)
}
