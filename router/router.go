package router

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Describes a route that maps from uncoming URL to backend service
type route struct {
	match   string
	scheme  string
	host    string
	replace string
	proxy   string
	re      *regexp.Regexp
}

// Rewrite an incoming URL, so that it is ready to be dispatched to a backend service
func (r *route) generate(req *http.Request) (urlstr, scheme, proxy string) {
	url := new(url.URL)
	*url = *req.URL
	url.Scheme = r.scheme
	url.Host = r.host
	url.Path = r.re.ReplaceAllString(url.Path, r.replace)
	return url.String(), r.scheme, r.proxy
}

// This holds the definition of a bunch of routes
type routeSet struct {
	routes map[string]*route
	re     *regexp.Regexp
}

// The Router interface is responsible for taking an incoming request and rewriting it
// for an appropriate backend.
type Router interface {
	// Rewrite an incoming request. The returned value 'routed' is true if the Router was
	// able to process the request.
	ProcessRoute(req *http.Request) (newurl, scheme, proxy string, routed bool)
}

func (r *routeSet) ProcessRoute(req *http.Request) (newurl, scheme, proxy string, routed bool) {
	re := r.re.FindString(req.RequestURI)
	generator, ok := r.routes[re]
	if !ok {
		return req.RequestURI, "http", "", false
	}
	newurl, scheme, proxy = generator.generate(req)
	return newurl, scheme, proxy, true
}

// Top-level configuration of a router
type RouterConfig []struct {
	Matches []struct {
		Match string `json:"match"` // /assetcap
		Route string `json:"route"`
		Proxy string `json:"proxy"`
	} `json:"matches"`
	Target string `json:"target"` // http://127.0.0.1:2000/
	Scheme string `json:"scheme"`
}

// Turn a configuration into a runnable Router
func NewRouter(config *RouterConfig) (router Router, err error) {
	defer func() {
		if e := recover(); e != nil {
			router = nil
			err = e.(error)
		}
	}()

	routeset := &routeSet{}
	routeset.routes = make(map[string]*route)
	routeset.re = regexp.MustCompile("^(/\\w*)/??")

	for _, target := range *config {
		for _, match := range target.Matches {
			parts := strings.Split(match.Route, "|")
			route := &route{}
			route.match = match.Match
			route.scheme = target.Scheme
			route.host = target.Target
			route.replace = parts[1]
			route.proxy = match.Proxy
			route.re = regexp.MustCompile(parts[0])
			routeset.routes[match.Match] = route
		}
	}

	return Router(routeset), nil
}

/*
Reads and parse a routing config file, and return a new Router object.

An example config file:

	[
		{
			"target": "server1",
			"scheme": "http",
			"matches": [
				{"match": "/s1p1", "route": "(.*)|$1"},
				{"match": "/s1p2", "route": "(.*)|$1"},
				{"match": "/s1p3", "route": "(.*)|$1"},
			]
		},
		{
			"target": "server2",
			"scheme": "http",
			"matches": [
				{"match": "/s2p1", "route": "/s2p1(.*)|/newpath1$1"},
				{"match": "/s2p2", "route": "/s2p2(.*)|$1"},
				{"match": "/s2p3", "route": "(.*)|$1"}
			]
		},
		{
			"target": "server3:9000",
			"scheme": "ws",
			"matches": [
				{"match": "/wws", "route":"(.*)|$1"}
			]
		}
	]

In the example above the following will happen assuming router is deployed on port 80 on server "server":

	http://server/s1p1                           -> http://server1/s1p1
	http://server/s1p2                           -> http://server1/s1p2
	http://server/s1p3/query?q=amount&order=asc  -> http://server1/s1p3/query?q=amount&order=asc

	http://server/s2p1/further/path/elements     -> http://server2/newpath1/further/path/elements
	http://server/s2p2/further/path/elements     -> http://server2/further/path/elements
	http://server/s2p3/further/path/elements     -> http://server2/s2p3/further/path/elements

	ws://server/wws                              -> ws://server3:9000/wws

*/
func ParseRoutes(configReader io.Reader) (*RouterConfig, error) {
	config := &RouterConfig{}
	decoder := json.NewDecoder(configReader)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}
	return config, nil
}
