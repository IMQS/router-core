/*
Package frontdoor provides proxy functionality for http and websockets.
This file provides the routing functionality for the connections. It uses a json routing file of the form :
[
	{"target":"server1",
	 "scheme":"http",
	 "matches":[
		 {"match":"/s1p1", "function":"none",  "replace":""},
		 {"match":"/s1p2", "function":"none",  "replace":""},
		 {"match":"/s1p3", "function":"none",  "replace":""}
	 ]},
	{"target":"server2",
	 "scheme":"http",
	 "matches":[
		 {"match":"/s2p1", "function":"replace", "replace":"/newpath1"},
		 {"match":"/s2p2",  "function":"remove",  "replace":""},
		 {"match":"/s2p3", "function":"none",    "replace":""}
     ]},
	{"target":"server3:9000",
	 "scheme":"ws",
	 "matches":[
		 {"match":"/wws", "function":"none", "replace":""}
	 ]}
]
	
In the example above the following will happen assuming frontdoor is deployed on port 80 on server "server":

http://server/s1p1                          -> http://server1/s1p1
http://server/s1p2                          -> http://server1/s1p2
http://server/s1p3/query?q=amount&order=asc -> http://server1/s1/p3/query?q=amount&order=asc

http://server/s2p1/further/path/elements     -> http://server2/newpath1/further/path/elements
http://server/s2p2/further/path/elements     -> http://server2/further/path/elements
http://server/s2p3/further/path/elements     -> http://server2/s2p3/further/path/elements

ws://server/wws                              -> ws://server3:9000/wws

*/
package frontdoor

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Route struct {
	match    string
	scheme   string
	host     string
	function string
	replace  string
}

func (r *Route) Generate(req *http.Request) (string, string) {
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

type Router interface {
	Generate(req *http.Request) (string, string)
}

type Routes map[string]Router

func NewRoutes() *Routes {

	type frontdoor_config []struct {
		Matches []struct {
			Function string `json:"function"` // none
			Match    string `json:"match"`    // /assetcap
			Replace  string `json:"replace"`  //
		} `json:"matches"`
		Target string `json:"target"` // http://127.0.0.1:2000/
		Scheme string `json:"scheme"`
	}

	r := make(Routes)
	file, err := os.Open("c:\\imqsbin\\conf\\frontdoor_config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	var top frontdoor_config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&top)
	if err != nil {
		file.Close()
		log.Fatal(err)
	}

	for _, target := range top {
		for _, match := range target.Matches {
			r[match.Match] = &Route{match.Match, target.Scheme, target.Target, match.Function, match.Replace}
		}
	}

	return &r
}

func (r *Routes) Route(req *http.Request) (string, string) {
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
		return req.RequestURI, "http"
	}
	return router.Generate(req)
}
