package router

// This file contains utils to print out data structures and can be used during testing and/or debugging.

import (
	"fmt"
	"net/http"
	"net/url"
)

func printHeader(h http.Header) {
	for k, vv := range h {
		for _, v := range vv {
			fmt.Printf("\t%s:%s\n", k, v)
		}
	}
}

func printRequest(req *http.Request, title string) {
	fmt.Printf("%s ###########################\n\n", title)
	fmt.Printf("Method %s\n", req.Method)
	printURL(req.URL)
	fmt.Printf("Proto %s\n", req.Proto)
	fmt.Printf("ProtoMajor %d\n", req.ProtoMajor)
	fmt.Printf("ProtoMinor %d\n", req.ProtoMinor)
	printHeader(req.Header)
	// Body ?
	fmt.Printf("ContentLength %d\n", req.ContentLength)
	fmt.Printf("TransferEncoding %v\n", req.TransferEncoding)
	fmt.Printf("Close %v\n", req.Close)
	fmt.Printf("Host %s\n\n\n", req.Host)
	fmt.Printf("RequestURI %s\n\n\n", req.RequestURI)
	fmt.Println("#############################\n\n")
}

func printResponse(resp *http.Response, title string) {
	fmt.Printf("%s===================\n\n", title)
	fmt.Printf("Status %s\n", resp.Status)
	fmt.Printf("StatusCode %d\n", resp.StatusCode)
	fmt.Printf("Proto %s\n", resp.Proto)
	printHeader(resp.Header)
	fmt.Printf("ContentLength %d\n", resp.ContentLength)
	fmt.Printf("TransferEncoding %s\n", resp.TransferEncoding)
	fmt.Printf("Close %v\n", resp.Close)
	printHeader(resp.Trailer)
	fmt.Println("=====================\n\n")
}

func printURL(url *url.URL) {
	fmt.Println("**********URL*************")
	fmt.Printf("Scheme : %s\n", url.Scheme)
	fmt.Printf("Opaque : %s\n", url.Opaque)
	fmt.Printf("User : %s\n", url.User)
	fmt.Printf("Host : %s\n", url.Host)
	fmt.Printf("Path : %s\n", url.Path)
	fmt.Printf("RawQuery : %s\n", url.RawQuery)
	fmt.Printf("Fragment : %s\n", url.Fragment)
	fmt.Println("*************************")
}
