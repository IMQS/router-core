// Package main provides the kickoff of the frontdoor server. This server proxies http and websocket requests to backend servers.
package main

import (
	"github.com/IMQS/router-core/router"
)

func main() {
	s := router.NewServer("")
	s.HttpServer.Addr = ":80"
	s.ListenAndServe()
}
