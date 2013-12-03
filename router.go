package main

import (
	"fmt"
	"github.com/IMQS/router-core/router"
	"log"
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
	args := os.Args[1:]
	if len(args) == 0 {
		showHelp()
		return 0
	}

	configpath := ""
	arg := args[0]
	if arg[0:2] == "-c" {
		configpath = args[1]
	}

	if configpath == "" {
		showHelp()
		return 0
	}

	configfile, err := os.Open(configpath)
	if err != nil {
		panic("Unable to open config file: " + err.Error())
	}

	handler := func() error {
		config, errCfg := router.ParseRoutes(configfile)
		if errCfg != nil {
			return errCfg
		}
		server, err := router.NewServer(config)
		if err != nil {
			return err
		}
		server.HttpServer.Addr = ":80"
		log.Fatal(server.ListenAndServe())
		return nil
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

func showHelp() {
	help := `imqsrouter -c configfile`
	fmt.Print(help)
}
