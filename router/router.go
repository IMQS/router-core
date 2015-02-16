package router

import (
	"fmt"
	ms_http "github.com/MSOpenTech/azure-sdk-for-go/core/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type scheme string

const (
	scheme_unknown scheme = ""
	scheme_ws             = "ws"
	scheme_http           = "http"
)

// A target URL
type target struct {
	baseUrl           string                // The replacement string is appended to this
	useProxy          bool                  // True if we route this via the proxy
	requirePermission string                // If non-empty, then first authorize before continuing
	auth              targetPassThroughAuth // Special authentication rules for this target
}

type targetPassThroughAuth struct {
	config       ConfigPassThroughAuth
	token        string
	tokenExpires time.Time
	lock         sync.RWMutex
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

	proxy *url.URL

	/////////////////////////////////////////////////
	// Cached state.
	// The following state is computed from 'routes'.
	prefixHash    map[string]*route // Keys are everything up to the first open parenthesis character '('
	prefixLengths []int             // Descending list of unique prefix lengths
}

// The Router interface is responsible for taking an incoming request and rewriting it
// for an appropriate backend.
type Router interface {
	// Rewrite an incoming request. If newurl is a blank string, then the URL does not match any route.
	ProcessRoute(uri *url.URL) (newurl string, requirePermission string, passThroughAuth *targetPassThroughAuth)
	// Return the URL of a proxy to use for a given request
	GetProxy(req *ms_http.Request) (*url.URL, error)
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

func (r *routeSet) ProcessRoute(uri *url.URL) (newurl string, requirePermission string, passThroughAuth *targetPassThroughAuth) {
	route := r.match(uri)
	if route == nil {
		return "", "", nil
	}

	rewritten := route.match_re.ReplaceAllString(uri.RequestURI(), route.target.baseUrl+route.replace)

	return rewritten, route.target.requirePermission, &route.target.auth
}

func (r *routeSet) GetProxy(req *ms_http.Request) (*url.URL, error) {
	route := r.match(req.URL)
	if route == nil || !route.target.useProxy {
		return nil, nil
	}
	return r.proxy, nil
}

func (r *routeSet) match(uri *url.URL) *route {
	// Match from longest prefix to shortest
	// Note that we match only on PATH, not on the full URI - so anything behind the question mark is
	// not going to be matched. That's purely a "stupid" performance optimization. If you need to match
	// behind the question mark, then just go ahead and change this code to match on RequestURI() instead
	// of on Path.
	for _, length := range r.prefixLengths {
		if len(uri.Path) >= length {
			if route := r.prefixHash[uri.Path[:length]]; route != nil {
				return route
			}
		}
	}
	return nil
}

// Turn a configuration into a runnable Router
func NewRouter(config *Config) (Router, error) {
	rs := &routeSet{}

	err := config.verify()
	if err != nil {
		return nil, err
	}

	if config.Proxy != "" {
		rs.proxy, _ = url.Parse(config.Proxy) // config.verify() ensures that the proxy is a legal URL
	}

	targets := map[string]*target{}
	for name, ctarget := range config.Targets {
		t := &target{}
		t.baseUrl = ctarget.URL
		t.useProxy = ctarget.UseProxy
		t.requirePermission = ctarget.RequirePermission
		t.auth.config = ctarget.PassThroughAuth
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
