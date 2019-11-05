package src

import "flag"

func Run() {
	configPath := flag.String("c", "config.json", "config file path")
	c := (&config{}).init(*configPath)
	s := (&server{config: *c}).init()
	s.server()
}
