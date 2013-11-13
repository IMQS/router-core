package frontdoor

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
	//PrintURL(url)
	//fmt.Println(url)
	url.Scheme = r.scheme
	url.Host = r.host
	//fmt.Println(url.Path)
	switch r.function {
	case "remove":
		url.Path = strings.Replace(url.Path, r.match, "", 1)
	case "replace":
		url.Path = strings.Replace(url.Path, r.match, r.replace, 1)
	}
	fmt.Println(url.String())
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
	re := regexp.MustCompile(`^/(\w+)/`).FindString(req.RequestURI)
	switch {
	case len(re) == 0:
		re = "/"
	case len(re) > 0:
		re = re[:len(re)-1]
	}
	//fmt.Printf("Search key : %s\n", re)
	if router, ok = (*r)[re]; ok == false {
		//fmt.Printf("Generate : %s : %s\n", req.RequestURI, re)
		return req.RequestURI, "http"
	}
	return router.Generate(req)
}
