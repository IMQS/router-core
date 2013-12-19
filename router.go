package main

import (
	"flag"
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

	flags := flag.NewFlagSet("router", flag.ExitOnError)
	flags.String("accesslog", "c:\\imqsvar\\logs\\router_access.log", "access log file")
	flags.String("errorlog", "c:\\imqsvar\\logs\\router_error.log", "error log file")
	flags.String("mainconfig", "c:\\imqsbin\\bin\\router_config.json", "main config file for router")
	flags.String("clientconfig", "c:\\imqsbin\\conf\\router_config.json", "client specific overrides config file for router")
	flags.String("proxy", "", "proxy server:port to use")
	flags.Bool("disablekeepalive", false, "Disable Keep Alives")
	flags.Uint("maxidleconnections", 50, "Maximum Idle Connections")
	flags.Uint("responseheadertimeout", 60, "Header Timeout")
	if len(os.Args) > 1 {
		flags.Parse(os.Args[1:])
	}

	handler := func() error {
		config, errCfg := router.ParseRoutes(flags.Lookup("mainconfig").Value.String(),
			flags.Lookup("clientconfig").Value.String())
		if errCfg != nil {
			return errCfg
		}
		server, err := router.NewServer(config, flags)
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
