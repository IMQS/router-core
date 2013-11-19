package router

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

/*
Route is used internally to generate the new URL for a specific path match.
*/
type route struct {
	match    string
	scheme   string
	host     string
	function string
	replace  string
}

/*
Generate is the main function on routing. This determines the new URL and implements
the remove and replace functions on the new path.
*/
func (r *route) generate(req *http.Request) (string, string) {
	url := new(url.URL)
	*url = *req.URL
	url.Scheme = r.scheme
	url.Host = r.host
	switch r.function {
	case "remove":
		url.Path = strings.Replace(url.Path, r.match, "", 1)
	case "replace":
		url.Path = strings.Replace(url.Path, r.match, r.replace, 1)
	}
	return url.String(), r.scheme
}

// Router interface to use in the lookup list.
type Router interface {
	generate(req *http.Request) (string, string)
}

/*
Routes is the main entrypoint into the router functionality. This will typically be used as follows:

	type Server struct {
		...
		routes *Routes
		...
	}

	func NewServer() *Server {
		s := &Server{}
		...
		s.routes = NewRoutes()
		...
		return s
	}

*/
type Routes map[string]Router

/*
NewRoutes reads, parses and stores a routing config file. This is the way to create new routes.

The config file provides the routing functionality for the connections.

An example config file:

	[
		{
			"target": "server1",
			"scheme": "http",
			"matches": [
				{"match": "/s1p1", "function": "none",  "replace": ""},
				{"match": "/s1p2", "function": "none",  "replace": ""},
				{"match": "/s1p3", "function": "none",  "replace": ""}
			]
		},
		{
			"target": "server2",
			"scheme": "http",
			"matches": [
				{"match": "/s2p1", "function": "replace", "replace": "/newpath1"},
				{"match": "/s2p2", "function": "remove",  "replace": ""},
				{"match": "/s2p3", "function": "none",    "replace": ""}
			]
		},
		{
			"target": "server3:9000",
			"scheme": "ws",
			"matches": [
				{"match": "/wws", "function": "none", "replace": ""}
			]
		}
	]

In the example above the following will happen assuming router is deployed on port 80 on server "server":

	http://server/s1p1                           -> http://server1/s1p1
	http://server/s1p2                           -> http://server1/s1p2
	http://server/s1p3/query?q=amount&order=asc  -> http://server1/s1/p3/query?q=amount&order=asc

	http://server/s2p1/further/path/elements     -> http://server2/newpath1/further/path/elements
	http://server/s2p2/further/path/elements     -> http://server2/further/path/elements
	http://server/s2p3/further/path/elements     -> http://server2/s2p3/further/path/elements

	ws://server/wws                              -> ws://server3:9000/wws

*/
func NewRoutes(configfilename string) *Routes {

	type router_config []struct {
		Matches []struct {
			Function string `json:"function"` // none
			Match    string `json:"match"`    // /assetcap
			Replace  string `json:"replace"`  //
		} `json:"matches"`
		Target string `json:"target"` // http://127.0.0.1:2000/
		Scheme string `json:"scheme"`
	}
	if len(configfilename) == 0 {
		// Use standard config file
		configfilename = "c:\\imqsbin\\conf\\router_config.json"
	}
	r := make(Routes)
	file, err := os.Open(configfilename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	var top router_config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&top)
	if err != nil {
		file.Close()
		log.Fatal(err)
	}

	for _, target := range top {
		for _, match := range target.Matches {
			r[match.Match] = &route{match.Match, target.Scheme, target.Target, match.Function, match.Replace}
		}
	}

	return &r
}

/*
Route is where all the good stuff happens. Typical usage (to continue the example above):

	func (s *Server) ServeHTTP(..., req *http.Request) {
		newurl, scheme := s.Routes.Route(req)
		switch scheme {
		case "http":
			s.forwardHttp(w, req, newurl)
		case "ws":
			s.forwardWebsocket(w, req, newurl)
		}
	}
*/
func (r *Routes) Route(req *http.Request) (string, string, bool) {
	var router Router
	var ok bool
	re := strings.Split(req.RequestURI, "/")[1]
	switch {
	case len(re) == 0:
		re = "/"
	case len(re) > 0:
		re = "/" + re
	}
	if router, ok = (*r)[re]; ok == false {
		return req.RequestURI, "http", false
	}
	newurl, scheme := router.generate(req)
	return newurl, scheme, true
}
