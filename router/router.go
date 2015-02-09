package router

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

type scheme string

const (
	scheme_unknown scheme = ""
	scheme_ws             = "ws"
	scheme_http           = "http"
)

// A target URL
type target struct {
	baseUrl  string // The replacement string is appended to this
	useProxy bool   // True if we route this via the proxy
}

// A route that maps from incoming URL to a target URL
type route struct {
	match    string
	match_re *regexp.Regexp // Parsed regular expression of 'match'
	replace  string
	target   *target
}

func parse_scheme(targetUrl string) scheme {
	switch {
	case strings.Index(targetUrl, "ws") == 0:
		return scheme_ws
	case strings.Index(targetUrl, "http") == 0:
		return scheme_http
	}
	return scheme_unknown
}

func (r *route) scheme() scheme {
	return parse_scheme(r.target.baseUrl)
}

// Router configuration when live
type routeSet struct {
	routes []*route

	proxy string

	/////////////////////////////////////////////////
	// Cached state.
	// The following state is computed from 'routes'.
	prefixHash    map[string]*route // Keys are everything up to the first open parenthesis character '('
	prefixLengths []int             // Descending list of unique prefix lengths
}

// The Router interface is responsible for taking an incoming request and rewriting it
// for an appropriate backend.
type Router interface {
	// Rewrite an incoming request.
	ProcessRoute(req *http.Request) (newurl, proxy string, success bool)
}

func (r *routeSet) computeCaches() error {
	allLengths := map[int]bool{}
	r.prefixHash = make(map[string]*route)
	for _, route := range r.routes {
		openParen := strings.Index(route.match, "(")
		key := ""
		if openParen == -1 {
			// route has no regex captures
			key = route.match
		} else {
			key = route.match[:openParen]
		}
		r.prefixHash[key] = route
		allLengths[len(key)] = true
		var err error
		route.match_re, err = regexp.Compile(route.match)
		if err != nil {
			return fmt.Errorf("Failed to compile regex '%v': %v", route.match, err)
		}
	}

	// Produce descending list of unique prefix lengths
	r.prefixLengths = []int{}
	for x, _ := range allLengths {
		r.prefixLengths = append(r.prefixLengths, x)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(r.prefixLengths)))

	return nil
}

func (r *routeSet) ProcessRoute(req *http.Request) (newurl, proxy string, success bool) {

	// Match from longest prefix to shortest
	var route *route
	for _, length := range r.prefixLengths {
		if len(req.RequestURI) >= length {
			if route = r.prefixHash[req.RequestURI[:length]]; route != nil {
				break
			}
		}
	}

	if route == nil {
		return "", "", false
	}

	rewritten := route.match_re.ReplaceAllString(req.RequestURI, route.target.baseUrl+route.replace)

	if route.target.useProxy {
		proxy = r.proxy
	}
	return rewritten, proxy, true
}

// Turn a configuration into a runnable Router
func NewRouter(config *Config) (Router, error) {
	rs := &routeSet{}
	rs.proxy = config.Proxy

	err := config.verify()
	if err != nil {
		return nil, err
	}

	targets := map[string]*target{}
	for name, ctarget := range config.Targets {
		t := &target{}
		t.baseUrl = ctarget.URL
		t.useProxy = ctarget.UseProxy
		targets[name] = t
	}

	for match, replace := range config.Routes {
		route := &route{}
		route.match = match
		named_target, named_suffix := split_named_target(replace)
		if len(named_target) != 0 {
			if targets[named_target] == nil {
				return nil, fmt.Errorf("Route target (%v) not defined", named_target)
			}
			route.target = targets[named_target]
			route.replace = named_suffix
		} else {
			route.target = &target{}
			route.target.useProxy = false
			route.target.baseUrl = ""
			route.replace = replace
		}
		rs.routes = append(rs.routes, route)
	}

	if err = rs.computeCaches(); err != nil {
		return nil, err
	}

	return rs, nil
}
