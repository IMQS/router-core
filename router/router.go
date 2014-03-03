package router

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
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
	routes   map[string]*route
	catchAll *route // Specified by matching "/", this route is executed if no other routes match
	re       *regexp.Regexp
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
	if !ok && r.catchAll != nil {
		ok = true
		generator = r.catchAll
	}
	if !ok {
		return req.RequestURI, "http", "", false
	}
	newurl, scheme, proxy = generator.generate(req)
	return newurl, scheme, proxy, true
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

	for target, conf := range *config {
		for path, match := range conf.Matches {
			parts := strings.Split(match.Route, "|")
			scheme := target[:strings.Index(target, ":")]
			host := target[strings.Index(target, "//")+2:]
			route := &route{}
			route.match = path
			route.scheme = scheme
			route.host = host
			route.replace = parts[1]
			route.proxy = conf.Proxy
			route.re = regexp.MustCompile(parts[0])
			routeset.routes[path] = route
			if path == "/" {
				routeset.catchAll = route
			}
		}
	}

	return Router(routeset), nil
}

/*
Reads and parse a routing config file, and return a new Router object.

An example config file:
{
	"http://server1":{
		"proxy":"",
		"matches":{
			"/s1p1":{"route":"(.*)|$1"},
			"/s1p2":{"route":"(.*)|$1"},
			"/s1p3":{"route":"(.*)|$1"}
		}},
	"http://server2":{
		"proxy":"",
		"matches":{
			"/s2p1":{"route":"/s2p1(.*)|/newpath$1"},
			"/s2p2":{"route":"/s2p2(.*)|$1"},
			"/s2p3":{"route":"(.*)|$1"}
		}},
	"ws://server3:9000":{
		"proxy":"",
		"matches":{
			"/wws":{"route":"(.*)|/$1"}
		}}
}
In the example above the following will happen assuming router is deployed on port 80 on server "server":

	http://server/s1p1                           -> http://server1/s1p1
	http://server/s1p2                           -> http://server1/s1p2
	http://server/s1p3/query?q=amount&order=asc  -> http://server1/s1p3/query?q=amount&order=asc

	http://server/s2p1/further/path/elements     -> http://server2/newpath1/further/path/elements
	http://server/s2p2/further/path/elements     -> http://server2/further/path/elements
	http://server/s2p3/further/path/elements     -> http://server2/s2p3/further/path/elements

	ws://server/wws                              -> ws://server3:9000/wws

*/
type Routes map[string]struct {
	Route string `json:"route"`
}

// Top-level configuration of a router
type RouterConfig map[string]struct {
	Proxy   string `json:"proxy"`
	Matches Routes
}

func mergeConfigs(dst, src *RouterConfig) error {
	for key, srcVal := range *src {
		if dstVal, ok := (*dst)[key]; ok {
			// Have same target merge src into dst, for now only proxy and new routes
			if proxy := srcVal.Proxy; len(proxy) > 0 {
				dstVal.Proxy = proxy
			}
			(*dst)[key] = dstVal
		}
	}
	return nil
}

func mergeMatches(dst, src Routes) {
	// ToDo
}

// Updated to have a global config file and a client specific file. The global config file gets overriden by the client config file.
func ParseRoutes(mainConfig interface{}) (*RouterConfig, error) {
	main, err := parseRoute(mainConfig)
	if err != nil {
		return nil, err
	}

	return main, nil
}

func parseRoute(config interface{}) (*RouterConfig, error) {
	var reader io.Reader
	var err error
	switch config.(type) {
	case io.Reader:
		reader = config.(io.Reader)
	case string:
		file, err := os.Open(config.(string))
		if err != nil {
			return nil, err
		}
		defer file.Close()
		reader = file
	}
	result := &RouterConfig{}
	decoder := json.NewDecoder(reader)
	if err = decoder.Decode(result); err != nil {
		return nil, err
	}
	return result, nil
}
