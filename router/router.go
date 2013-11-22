package router

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

/*
Generator is used internally to generate the new URL for a specific path match.
*/
type generator struct {
	match   string
	scheme  string
	host    string
	replace string
	re      *regexp.Regexp
}

/*
Generate is the main function on routing. This determines the new URL and implements
the remove and replace functions on the new path.
*/
func (g *generator) generate(req *http.Request) (urlstr string, scheme string) {
	url := new(url.URL)
	*url = *req.URL
	url.Scheme = g.scheme
	scheme = g.scheme
	url.Host = g.host
	url.Path = g.re.ReplaceAllString(url.Path, g.replace)
	urlstr = url.String()
	return
}

// Generator interface to use in the lookup list.
type Generator interface {
	generate(req *http.Request) (string, string)
}

/*
router is the container holding all the information required for creating a new url. It also has the
base regex used to parse the intitial url to find an index into the map

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
type router struct {
	routes map[string]Generator
	re     *regexp.Regexp
}

/*
Router is the main entrypoint into the router functionality. This will typically be used as follows:

	type Server struct {
		...
		router Routes
		...
	}

	func NewServer() *Server {
		s := &Server{}
		...
		s.router = NewRouter()
		...
		return s
	}

*/
type Router interface {
	Route(req *http.Request) (newurl, scheme string, routed bool)
}

/*
NewRouter reads, parses and stores a routing config file. This is the way to create new routes.

The config file provides the routing functionality for the connections.

An example config file:

	[
		{
			"target": "server1",
			"scheme": "http",
			"matches": [
				{"match": "/s1p1", "route":"(.*)|$1"},
				{"match": "/s1p2", "route":"(.*)|$1"},
				{"match": "/s1p3", "route":"(.*)|$1"},
			]
		},
		{
			"target": "server2",
			"scheme": "http",
			"matches": [
				{"match": "/s2p1", "route":"/s2p1(.*)|/newpath1$1"},
				{"match": "/s2p2", "route":"/s2p2(.*)|$1"},
				{"match": "/s2p3", "route":"(.*)|$1"}
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
func NewRouter(configfilename string) (Router, error) {

	type router_config []struct {
		Matches []struct {
			Match string `json:"match"` // /assetcap
			Route string `json:"route"`
		} `json:"matches"`
		Target string `json:"target"` // http://127.0.0.1:2000/
		Scheme string `json:"scheme"`
	}

	r := router{make(map[string]Generator), regexp.MustCompile("^(/\\w*)/??")}

	filename, err := filepath.Abs(configfilename)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var top router_config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&top)
	if err != nil {
		file.Close()
		return nil, err
	}

	for _, target := range top {
		for _, match := range target.Matches {
			parts := strings.Split(match.Route, "|")
			r.routes[match.Match] = &generator{match.Match, target.Scheme, target.Target,
				parts[1], regexp.MustCompile(parts[0])}
		}
	}

	return Router(&r), nil
}

/*
Route is where all the good stuff happens. Typical usage (to continue the example above):

	func (s *Server) ServeHTTP(..., req *http.Request) {
		newurl, scheme := s.Router.Route(req)
		switch scheme {
		case "http":
			s.forwardHttp(w, req, newurl)
		case "ws":
			s.forwardWebsocket(w, req, newurl)
		}
	}
*/
func (r *router) Route(req *http.Request) (newurl, scheme string, routed bool) {
	re := r.re.FindString(req.RequestURI)
	generator, ok := r.routes[re]
	if ok == false {
		return req.RequestURI, "http", false
	}
	newurl, scheme = generator.generate(req)
	return newurl, scheme, true
}
