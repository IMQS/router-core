package router

import (
	"net/http"
	"net/url"
	"testing"
)

// These tests do not actually launch a live router. They simply test abstract functionality.

func routeSetFromConfig(t *testing.T, cfg_json string) *routeSet {
	cfg := &Config{}
	err := cfg.LoadString(cfg_json)
	if err != nil {
		t.Fatal(err)
	}
	translator, err := newUrlTranslator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return translator.(*routeSet)
}

func verifyRoute(t *testing.T, rs *routeSet, inUrl string, expectOutUrl string) {
	req := http.Request{}
	req.RequestURI = inUrl
	uri, _ := url.Parse(inUrl)
	newUrl, _, _ := rs.processRoute(uri)
	if newUrl != expectOutUrl {
		t.Errorf("route match failed: %v -> %v (expected %v)", inUrl, newUrl, expectOutUrl)
	}
}

func TestUnitRouteMatching(t *testing.T) {
	// Various tests, including giving priority to longer matches
	rs := routeSetFromConfig(t, `
		{"Routes": {
			"/no-trailing-slash(.*)": "http://abc.com/555$1",
			"/abc/long/(.*)": "http://abc.com/long/$1",
			"/abc/(.*)": "http://abc.com/123/$1",
			"/static": "http://abc.com/noise",
			"/(.*)": "http://127.0.0.1/www/$1"
		}}`)

	verifyRoute(t, rs, "/abc/long/777", "http://abc.com/long/777") // /abc/long/ must match before /abc/ or /
	verifyRoute(t, rs, "/static", "http://abc.com/noise")          // route with no regex patterns
	verifyRoute(t, rs, "/abc/xyz/", "http://abc.com/123/xyz/")
	verifyRoute(t, rs, "/abc/xyz", "http://abc.com/123/xyz")
	verifyRoute(t, rs, "/abc/", "http://abc.com/123/")
	verifyRoute(t, rs, "/", "http://127.0.0.1/www/")
	verifyRoute(t, rs, "/1/2/3", "http://127.0.0.1/www/1/2/3")
	verifyRoute(t, rs, "/1/2/3/4/5/6/7/8/9/0/1/2/3/4/5/6/7/8/9/0/1/2/3/4/5/6/7/8/9/0", "http://127.0.0.1/www/1/2/3/4/5/6/7/8/9/0/1/2/3/4/5/6/7/8/9/0/1/2/3/4/5/6/7/8/9/0")
	verifyRoute(t, rs, "/no-trailing-slash666", "http://abc.com/555666")

	// Unmatched routes
	rs = routeSetFromConfig(t, `
			{"Routes": {
				"/abc/(.*)": "https://abc.com/123/$1"
			}}`)

	verifyRoute(t, rs, "/", "")
	verifyRoute(t, rs, "/abc", "")
	verifyRoute(t, rs, "/abc/", "https://abc.com/123/")

	// More than one capture
	rs = routeSetFromConfig(t, `
			{"Routes": {
				"/abc/([^/]*)/(.*)": "http://abc/$2/$1"
			}}`)

	verifyRoute(t, rs, "/abc/a/b", "http://abc/b/a")
}
