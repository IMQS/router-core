package main

import (
	"github.com/IMQS/router-core/router"
)

func main() {
	s := router.NewServer("c:\\imqsbin\\conf\\frontdoor_config.json")
	s.HttpServer.Addr = ":80"
	s.ListenAndServe()
}
