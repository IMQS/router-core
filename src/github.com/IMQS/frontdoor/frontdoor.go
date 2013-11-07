package main

import (
	"github.com/IMQS/frontdoor/frontdoor"
)

func main() {
	s := frontdoor.NewServer()
	s.HttpServer.Addr = ":8080"
	s.ListenAndServe()
}
