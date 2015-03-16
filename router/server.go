package router

import (
	"encoding/json"
	"fmt"
	ms_http "github.com/MSOpenTech/azure-sdk-for-go/core/http"
	"github.com/cespare/go-apachelog"
	"github.com/natefinch/lumberjack"
	"golang.org/x/net/websocket"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const imqsauth_url = "http://127.0.0.1:2003"
const imqsauth_cookie = "session"

var imqsauth_role2name map[int]string

// Router Server
type Server struct {
	HttpServer        *http.Server
	httpTransport     *ms_http.Transport
	debugRoutes       bool
	router            Router
	errorLog          *log.Logger
	listener          net.Listener
	listenerSecondary net.Listener
	waiter            sync.WaitGroup
	wsdlMatch         *regexp.Regexp // hack for serving static content
}

// NewServer creates a new server instance; starting up logging and creating a routing instance.
func NewServer(config *Config) (*Server, error) {
	if config.AccessLog == "" {
		return nil, fmt.Errorf("You must specify an AccessLog file")
	}
	if config.ErrorLog == "" {
		return nil, fmt.Errorf("You must specify an ErrorLog file")
	}
	var err error
	s := &Server{}
	s.HttpServer = &http.Server{}
	s.HttpServer.Handler = apachelog.NewHandler(s, openLog(config.AccessLog, os.Stdout))
	s.debugRoutes = config.DebugRoutes

	logFlags := log.Ldate | log.Ltime | log.Lmicroseconds
	errorLog := openLog(config.ErrorLog, os.Stderr)
	s.errorLog = log.New(errorLog, "", logFlags)
	log.SetOutput(errorLog)
	log.SetFlags(logFlags)

	if s.router, err = NewRouter(config); err != nil {
		return nil, err
	}

	s.httpTransport = &ms_http.Transport{
		DisableKeepAlives:     config.HTTP.DisableKeepAlive,
		MaxIdleConnsPerHost:   config.HTTP.MaxIdleConnections,
		DisableCompression:    true,
		ResponseHeaderTimeout: time.Second * time.Duration(config.HTTP.ResponseHeaderTimeout),
	}
	s.httpTransport.Proxy = func(req *ms_http.Request) (*url.URL, error) {
		return s.router.GetProxy(req)
	}

	s.errorLog.Print("Starting v0.03 with:")
	s.errorLog.Printf(" DisableKeepAlives: %v", config.HTTP.DisableKeepAlive)

	s.errorLog.Printf(" MaxIdleConnsPerHost: %v", config.HTTP.MaxIdleConnections)
	s.errorLog.Printf(" ResponseHeaderTimeout: %v", config.HTTP.ResponseHeaderTimeout)
	s.wsdlMatch = regexp.MustCompile(`([^/]\w+)\.(wsdl)$`)
	return s, nil
}

// Run the server
func (s *Server) ListenAndServe(httpPort, httpPortSecondary string) error {
	if httpPort == "" {
		httpPort = ":http"
	}

	run := func(listener *net.Listener, port string, done chan error) {
		var err error
		for {
			if *listener, err = net.Listen("tcp", port); err != nil {
				s.errorLog.Printf("In Listen error : %s\n", err.Error())
				break
			}
			err = s.HttpServer.Serve(*listener)
			if err != nil {
				if strings.Contains(err.Error(), "specified network name is no longer available") {
					s.errorLog.Println("Restarting - error 64")
				} else {
					break
				}
			}
		}
		done <- err
	}

	var err error
	err1 := make(chan error)
	go run(&s.listener, httpPort, err1)
	if httpPortSecondary != "" {
		err2 := make(chan error)
		go run(&s.listenerSecondary, httpPortSecondary, err2)
		err = <-err2
	}
	if err == nil {
		err = <-err1
	}
	return err
}

// Detect illegal requests
func (s *Server) isLegalRequest(req *http.Request) bool {
	// We were getting a whole lot of requests to the 'telco' server where the hostname was "yahoo.mail.com".
	if req.URL.Host == "yahoo.mail.com" {
		s.errorLog.Printf("Illegal hostname (%s) - closing connection", req.URL.Host)
		return false
	}
	return true
}

/*
ServeHTTP is the single router access point to the frondoor server. All request are handled in this method.
 It uses Routes to generate the new url and then switches on scheme type to connect to the backend copying
between these pipes.
*/
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.waiter.Add(1)
	defer s.waiter.Done()

	// HACK! Doesn't belong here!
	// Catch wsdl here to statically serve.
	filename := s.wsdlMatch.FindString(req.RequestURI)
	if filename != "" {
		http.ServeFile(w, req, "C:\\imqsbin\\conf\\"+filename)
		return
	}

	// Detect malware, DOS, etc
	if !s.isLegalRequest(req) {
		http.Error(w, "", http.StatusTeapot)
		return
	}
	newurl, requirePermission, passThroughAuth := s.router.ProcessRoute(req.URL)

	if s.debugRoutes {
		s.errorLog.Printf("(%v) -> (%v)", req.RequestURI, newurl)
	}

	if newurl == "" {
		http.Error(w, "Route not found", http.StatusNotFound)
		return
	}

	if !s.authorize(w, req, requirePermission) {
		return
	}

	if !authPassThrough(s.errorLog, w, req, passThroughAuth) {
		return
	}

	switch parse_scheme(newurl) {
	case "http":
		s.forwardHttp(w, req, newurl)
	case "ws":
		s.forwardWebsocket(w, req, newurl)
	}
}

/*
forwardHTTP connects to all http scheme backends and copies bidirectionaly between the incomming
connections and the backend connections. It also copies required HTTP headers between the connections making the
router "middle man" invisible to incomming connections.
The body part of both requests and responses are implemented as Readers, thus allowing the body contents
to be copied directly down the sockets, negating the requirement to have a buffer here. This allows all
http bodies, i.e. chunked, to pass through.

On the removal of the "Connection: close" header:
Leaving "Connection: close" is going to instruct the backend to close the HTTP connection
after a single request, which is in conflict with HTTP keep alive. If s.httpTransport.DisableKeepAlives
is false, then we DO want to enable keep alives. It might be better to only remove this header
if s.httpTransport.DisableKeepAlives is true, but it seems prudent to just get rid of it completely.

This issue first became apparent when running the router behind nginx. The backend server behind
router would react to the "Connection: close" header by closing the TCP connection after
the response was sent. This would then result in s.httpTransport.RoundTrip(cleaned) returning
an EOF error when it tried to re-use that TCP connection.
*/
func (s *Server) forwardHttp(w http.ResponseWriter, req *http.Request, newurl string) {
	cleaned, err := ms_http.NewRequest(req.Method, newurl, req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	srcHost := req.Host
	dstHost := cleaned.Host

	copyheadersIn(srcHost, req.Header, dstHost, cleaned.Header)
	cleaned.Proto = req.Proto
	cleaned.ContentLength = req.ContentLength

	resp, err := s.httpTransport.RoundTrip(cleaned)
	if err != nil {
		s.errorLog.Println("HTTP RoundTrip error: " + err.Error())
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return
	}
	copyheadersOut(dstHost, resp.Header, srcHost, w.Header(), req.TLS != nil)
	w.WriteHeader(resp.StatusCode)

	if resp.Body != nil {
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	}
}

/*
forwardWebsocket does for websockets what forwardHTTP does for http requests. A new socket connection is made to the backend and messages are forwarded both ways.
*/
func (s *Server) forwardWebsocket(w http.ResponseWriter, req *http.Request, newurl string) {
	myHandler := func(con *websocket.Conn) {
		origin := "http://localhost"
		config, errCfg := websocket.NewConfig(newurl, origin)
		if errCfg != nil {
			s.errorLog.Printf("Error with config: %v\n", errCfg.Error())
			return
		}
		backend, errOpen := websocket.DialConfig(config)
		if errOpen != nil {
			s.errorLog.Printf("Error with websocket.DialConfig: %v\n", errOpen.Error())
			return
		}
		copy := func(fromSocket *websocket.Conn, toSocket *websocket.Conn, toBackend bool, done chan bool) {

			for {
				var data string
				var err error
				err = websocket.Message.Receive(fromSocket, &data)
				if err == io.EOF {
					s.errorLog.Printf("Closing connection. EOF")
					fromSocket.Close()
					toSocket.Close()
					break
				}
				if err != nil && err != io.EOF {
					break
				}
				if e := websocket.Message.Send(toSocket, data); e != nil {
					break
				}
			}

			done <- true
		}

		tobackend := make(chan bool)
		go copy(con, backend, true, tobackend)
		frombackend := make(chan bool)
		go copy(backend, con, false, frombackend)
		<-tobackend
		<-frombackend
	}

	wsServer := &websocket.Server{}
	wsServer.Handler = myHandler
	wsServer.ServeHTTP(w, req)
}

// Returns true if the request should continue to be passed through the router
// We make a roun-trip to imqsauth here to check the credentials of the incoming request.
// This adds about a 0.5ms latency to the request. It might be worthwhile to embed
// imqsauth inside imqsrouter.
func (s *Server) authorize(w http.ResponseWriter, req *http.Request, requirePermission string) bool {
	if requirePermission == "" {
		return true
	}

	authReq, err := ms_http.NewRequest("GET", imqsauth_url+"/check", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	headAuth := req.Header.Get("Authorization")
	if headAuth != "" {
		authReq.Header.Set("Authorization", headAuth)
	}
	cookieSession, _ := req.Cookie(imqsauth_cookie)
	if cookieSession != nil {
		authReq.AddCookie(copyCookieToMSHTTP(cookieSession))
	}

	authResp, err := s.httpTransport.RoundTrip(authReq)
	if err != nil {
		s.errorLog.Println("HTTP RoundTrip error: " + err.Error())
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return false
	}
	defer authResp.Body.Close()

	respBodyBytes, _ := ioutil.ReadAll(authResp.Body)
	respBody := string(respBodyBytes)

	if authResp.StatusCode != http.StatusOK {
		s.errorLog.Printf("Unauthorized request to %v (%v)", req.URL.Path, authResp.StatusCode)
		http.Error(w, respBody, authResp.StatusCode)
		return false
	}

	authDecoded := &imqsAuthResponse{}
	if err = json.Unmarshal(respBodyBytes, authDecoded); err != nil {
		s.errorLog.Printf("Error decoding imqsauth response: %v", err)
		http.Error(w, "Error decoding imqsauth response", http.StatusInternalServerError)
		return false
	}

	if !authDecoded.hasRole(requirePermission) {
		s.errorLog.Printf("Unauthorized request to %v (identity does not have role %v)", req.URL.Path, requirePermission)
		http.Error(w, "Insufficient permissions", http.StatusUnauthorized)
		return false
	}

	//s.errorLog.Printf("Authorized request to %v", req.URL.Path)
	//http.Error(w, fmt.Sprintf("You're alright! (%v)", respBody), http.StatusOK)

	return true
}

func (s *Server) Stop() {
	s.errorLog.Println("Shutting down...")
	if s.listener != nil {
		s.listener.Close()
	}

	if s.listenerSecondary != nil {
		s.listenerSecondary.Close()
	}
	s.waiter.Wait()
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type imqsAuthResponse struct {
	Identity string
	Roles    []string // Array of integer roles, stored as strings
}

func (r *imqsAuthResponse) hasRole(role string) bool {
	if role == "" {
		return false
	}
	// role_string will be "2", or "34", etc.
	for _, role_string := range r.Roles {
		role_int, _ := strconv.Atoi(role_string)
		if imqsauth_role2name[role_int] == role {
			return true
		}
	}
	return false
}

func copyCookieToMSHTTP(org *http.Cookie) *ms_http.Cookie {
	c := &ms_http.Cookie{
		Name:  org.Name,
		Value: org.Value,
	}
	return c
}

func copyheadersIn(srcHost string, src http.Header, dstHost string, dst ms_http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			if k == "Location" {
				// Example
				// Original  Location		http://example.com/files/abc
				// Rewritten Location		http://127.0.0.1:2005/abc
				// -- I'm not sure why we do this -- If in doubt, just delete this. It seems wrong.
				v = strings.Replace(v, srcHost, dstHost, 1)
			}
			if k == "Connection" && v == "close" {
				// See detailed explanation in top-level function comment
				continue
			}
			dst.Add(k, v)
		}
	}
}

func copyheadersOut(srcHost string, src ms_http.Header, dstHost string, dst http.Header, isHTTPS bool) {
	for k, vv := range src {
		for _, v := range vv {
			if k == "Location" {
				// Some servers will send a Location header, but that Location will be an internal network address, so we
				// need to rewrite it to be an external address. It may be wiser to just stripe the absolute portion of Location away,
				// just leaving a relative URL. This is all for Yellowfin's sake.
				v = strings.Replace(v, srcHost, dstHost, 1)
				if isHTTPS && strings.Index(v, "http:") == 0 {
					v = strings.Replace(v, "http:", "https:", 1)
				}
			}
			dst.Add(k, v)
		}
	}
}

func openLog(filename string, defaultWriter io.Writer) io.Writer {
	if filename == "" {
		return defaultWriter
	}
	return &lumberjack.Logger{
		Filename:   filename,
		MaxSize:    50, // megabytes
		MaxBackups: 3,
		MaxAge:     90, // days
	}
}

func init() {
	// This must be kept in sync with perms.go in imqsauth
	imqsauth_role2name = make(map[int]string)
	imqsauth_role2name[2] = "enabled"
}
