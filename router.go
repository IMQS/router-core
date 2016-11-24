package main

import (
	"flag"
	"fmt"
	"github.com/IMQS/router-core/router"
	"os"
)

func main() {
	os.Exit(realMain())
}

func realMain() (result int) {
	result = 0

	defer func() {
		if err := recover(); err != nil {
			result = 1
			fmt.Printf("%v\n", err)
		}
	}()

	flags := flag.NewFlagSet("router", flag.ExitOnError)
	configFile := flags.String("config", "", "Optional config file for testing")
	showHttpPort := flags.Bool("show-http-port", false, "print the http port to stdout and exit")

	if len(os.Args) > 1 {
		flags.Parse(os.Args[1:])
	}

	config := &router.Config{}
	err := config.LoadFile(*configFile)
	if err != nil {
		panic(fmt.Errorf("Error loading '%s': %v", *configFile, err))
	}

	if *showHttpPort {
		fmt.Printf("%v", config.HTTP.GetPort())
		result = 0
		return
	}

	server, err := router.NewServer(config)
	if err != nil {
		panic(fmt.Errorf("Error starting server: %v", err))
	}

	handler := func() error {
		return server.ListenAndServe()
	}

	handlerNoRet := func() {
		handler()
	}
	success := true
	if !router.RunAsService(handlerNoRet) {
		// Run in the foreground
		success = false
		fmt.Print(handler())
	}

	if success {
		result = 0
	} else {
		result = 1
	}
	return
}
