package main

import (
	"github.com/IMQS/frontdoor/frontdoor"
)

func main() {
	s := frontdoor.NewServer()
	s.HttpServer.Addr = ":80"
	s.ListenAndServe()
}
