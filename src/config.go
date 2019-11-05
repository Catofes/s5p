package src

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"

	"github.com/rs/zerolog"
)

type config struct {
	Listen string
	Rules  []string
	Debug  bool
	logger zerolog.Logger
}

func (s *config) init(path string) *config {
	s.Listen = "[::]:1080"
	d, e := ioutil.ReadFile(path)
	if e != nil {
		log.Fatal(e)
	}
	e = json.Unmarshal(d, s)
	if e != nil {
		log.Fatal(e)
	}
	s.logger = zerolog.New(os.Stdout)
	if s.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	}
	return s
}
