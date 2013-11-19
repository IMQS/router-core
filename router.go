package main

import (
	"github.com/IMQS/router-core/router"
)

func main() {
	s := router.NewServer("")
	s.HttpServer.Addr = ":80"
	s.ListenAndServe()
}
