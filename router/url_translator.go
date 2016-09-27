package router

import (
	"fmt"
	"github.com/IMQS/log"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type scheme string

const (
	scheme_unknown    scheme = ""
	scheme_ws                = "ws"
	scheme_http              = "http"
	scheme_https             = "https"
	scheme_httpbridge        = "httpbridge"
)

// A target URL
type target struct {
	baseUrl           string                // The replacement string is appended to this
	useProxy          bool                  // True if we route this via the proxy
	requirePermission string                // If non-empty, then first authorize before continuing
	auth              targetPassThroughAuth // Special authentication rules for this target
}

/*
Usage of targetPassThroughAuth fields:

PureHub:
	token
	tokenExpires

Yellowfin:
	tokenMap
	tokenLock

SitePro:
	none

ECS:
	none
*/
type targetPassThroughAuth struct {
	lock         sync.RWMutex // Guards access to all state except for "config", which is immutable
	config       ConfigPassThroughAuth
	token        string                 // A single token shared by all users of the system. "machine to machine", without any user-specific session.
	tokenExpires time.Time              // Expiry date of 'token'
	tokenMap     map[string]interface{} // Map from username to token. For user-specific sessions with another machine.
	tokenLock    map[string]bool        // If an entry exists in here for a username, then we are busy trying to log that user in.
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
	case targetUrl[0:3] == "ws:":
		return scheme_ws
	case targetUrl[0:5] == "http:":
		return scheme_http
	case targetUrl[0:6] == "https:":
		return scheme_https
	case targetUrl[0:11] == "httpbridge:":
		return scheme_httpbridge
	}
	return scheme_unknown
}

func (r *route) scheme() scheme {
	return parse_scheme(r.target.baseUrl)
}

// Router configuration when live.
//
// This implements the fast lookup from URL to target.
// It also performs various sanity checks when initialized.
//
// This type is exposed internally via the urlTranslator interface.
// Although this is the only implementation of that interface, by doing it this way,
// we are encapsulating the functionality of the routeSet from the rest of the program.
type routeSet struct {
	routes []*route

	proxy *url.URL

	/////////////////////////////////////////////////
	// Cached state.
	// The following state is computed from 'routes'.
	prefixHash    map[string]*route  // Keys are everything up to the first open parenthesis character '('
	prefixLengths []int              // Descending list of unique prefix lengths
	targetHash    map[string]*target // Keys are the hostname for each of the target routes setup in config
}

func newTarget() *target {
	t := &target{}
	t.auth.tokenMap = make(map[string]interface{})
	t.auth.tokenLock = make(map[string]bool)
	return t
}

// A urlTranslator is responsible for taking an incoming request and rewriting it for an appropriate backend.
type urlTranslator interface {
	// Rewrite an incoming request. If newurl is a blank string, then the URL does not match any route.
	processRoute(uri *url.URL) (newurl string, requirePermission string, passThroughAuth *targetPassThroughAuth)
	// Return the URL of a proxy to use for a given request
	getProxy(errLog *log.Logger, host string) (*url.URL, error)
	// Returns all routes
	allRoutes() []*route
}

func (r *routeSet) computeCaches() error {
	allLengths := map[int]bool{}
	r.prefixHash = make(map[string]*route)
	r.targetHash = make(map[string]*target)
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

		parsedUrl, errUrl := url.Parse(route.target.baseUrl)
		if errUrl != nil {
			return fmt.Errorf("Target URL format incorrect %v:%v", route.target.baseUrl, errUrl)
		}
		if parsedUrl.Host != "" {
			r.targetHash[parsedUrl.Host] = route.target
		}

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

func (r *routeSet) processRoute(uri *url.URL) (newurl string, requirePermission string, passThroughAuth *targetPassThroughAuth) {
	route := r.match(uri)
	if route == nil {
		return "", "", nil
	}

	rewritten := route.match_re.ReplaceAllString(uri.RequestURI(), route.target.baseUrl+route.replace)

	return rewritten, route.target.requirePermission, &route.target.auth
}

func (r *routeSet) getProxy(errLog *log.Logger, host string) (*url.URL, error) {
	if r.targetHash[host] == nil {
		errLog.Errorf("Nil target pointer found in hash for host %v", host)
		return nil, nil
	}
	if !r.targetHash[host].useProxy {
		return nil, nil
	}
	return r.proxy, nil
}

func (r *routeSet) allRoutes() []*route {
	return r.routes
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

// Ensure that httpbridge targets specify the httpbridge backend port number.
func (r *routeSet) verifyHttpBridgeURLs() error {
	for _, route := range r.routes {
		if route.scheme() == scheme_httpbridge {
			parsedURL, err := url.Parse(route.target.baseUrl)
			if err != nil {
				return fmt.Errorf(`Invalid replacement URL "%v": %v`, route.target.baseUrl, err)
			}
			port, _ := strconv.Atoi(parsedURL.Host)
			portRT := strconv.Itoa(port)
			if port == 0 || parsedURL.Host != portRT {
				return fmt.Errorf(`httpbridge target must specify a port number only. The "%v" portion of "%v" is invalid.`, parsedURL.Host, route.target.baseUrl)
			}
		}
	}
	return nil
}

// Turn a configuration into a runnable urlTranslator
func newUrlTranslator(config *Config) (urlTranslator, error) {
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
		t := newTarget()
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
			parsedUrl, errUrl := url.Parse(replace)
			if errUrl != nil {
				return nil, fmt.Errorf("Route replacement URL format incorrect %v:%v", replace, errUrl)
			}
			route.target = newTarget()
			route.target.useProxy = false
			route.target.baseUrl = parsedUrl.Scheme + "://" + parsedUrl.Host
			route.replace = parsedUrl.Path
		}
		rs.routes = append(rs.routes, route)
	}

	if err = rs.verifyHttpBridgeURLs(); err != nil {
		return nil, err
	}

	if err = rs.computeCaches(); err != nil {
		return nil, err
	}

	return rs, nil
}
