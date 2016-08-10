package router

// NOTE: It feels wrong to have to copy stuff out of the standard library and in here.
// Two places where we do that:
// 1. createSSLListener()
// 2. tcpKeepAliveListener
// It would be good to get rid of that. I think the thing forcing our hand here is apachelog.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/IMQS/log"
	"github.com/IMQS/serviceauth"
	ms_http "github.com/MSOpenTech/azure-sdk-for-go/core/http"
	// "github.com/cespare/hutil/apachelog" // Newer, but doesn't support websockets
	"github.com/IMQS/go-apachelog" // Older, but supports websockets. Forked to include time zone in access logs.
	"github.com/IMQS/httpbridge/go/src/httpbridge"
	"golang.org/x/net/websocket"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
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

// Router Server
type Server struct {
	HttpServer        *http.Server
	httpTransport     *ms_http.Transport
	configHttp        ConfigHTTP
	debugRoutes       bool
	translator        urlTranslator
	errorLog          *log.Logger
	listener          net.Listener
	listenerSecondary net.Listener
	listenerSSL       net.Listener
	waiter            sync.WaitGroup
	wsdlMatch         *regexp.Regexp             // hack for serving static content
	httpBridgeServers map[int]*httpbridge.Server // Keys of the map are httpbridge backend port numbers
}

// NewServer creates a new server instance; starting up logging and creating a routing instance.
func NewServer(config *Config) (*Server, error) {
	var err error
	s := &Server{}
	s.configHttp = config.HTTP
	s.HttpServer = &http.Server{}
	s.httpBridgeServers = map[int]*httpbridge.Server{}

	// Using newer apachelog (see comments in package includes list)
	//s.HttpServer.Handler = apachelog.NewHandler(`%h - %u %t "%r" %s %b %T`, s, openLog(config.AccessLog, os.Stdout))

	// Using older apachelog
	s.HttpServer.Handler = apachelog.NewHandler(s, openLog(config.AccessLog, os.Stdout))

	s.debugRoutes = config.DebugRoutes
	s.errorLog = log.New(pickLogfile(config.ErrorLog))
	if config.LogLevel != "" {
		if lev, err := log.ParseLevel(config.LogLevel); err != nil {
			s.errorLog.Errorf("%v", err)
		} else {
			s.errorLog.Level = lev
		}
	}

	if s.translator, err = newUrlTranslator(config); err != nil {
		return nil, err
	}

	s.httpTransport = &ms_http.Transport{
		DisableKeepAlives:     config.HTTP.DisableKeepAlive,
		MaxIdleConnsPerHost:   config.HTTP.MaxIdleConnections,
		DisableCompression:    true,
		ResponseHeaderTimeout: time.Second * time.Duration(config.HTTP.ResponseHeaderTimeout),
	}
	s.httpTransport.Proxy = func(req *ms_http.Request) (*url.URL, error) {
		return s.translator.getProxy(s.errorLog, req.URL.Host)
	}

	s.errorLog.Info("Router starting with:")
	s.errorLog.Infof(" DisableKeepAlives: %v", config.HTTP.DisableKeepAlive)
	s.errorLog.Infof(" MaxIdleConnsPerHost: %v", config.HTTP.MaxIdleConnections)
	s.errorLog.Infof(" ResponseHeaderTimeout: %v", config.HTTP.ResponseHeaderTimeout)
	s.wsdlMatch = regexp.MustCompile(`([^/]\w+)\.(wsdl)$`)
	return s, nil
}

// Run the server
func (s *Server) ListenAndServe() error {
	httpPort := fmt.Sprintf(":%v", s.configHttp.GetPort())
	httpPortSecondary := ""
	if s.configHttp.SecondaryPort != 0 {
		httpPortSecondary = fmt.Sprintf(":%v", s.configHttp.SecondaryPort)
	}
	sslPort := ""
	if s.configHttp.EnableHTTPS {
		sslPort = ":https"
		if s.configHttp.HTTPSPort != 0 {
			sslPort = fmt.Sprintf(":%v", s.configHttp.HTTPSPort)
		}
	}

	listenAndRunHTTP := func(listener *net.Listener, port string, done chan error) {
		var err error
		for {
			var ln net.Listener
			if ln, err = net.Listen("tcp", port); err != nil {
				s.errorLog.Errorf("net.Listen (port %v) error: %s\n", port, err.Error())
				break
			}
			*listener = tcpKeepAliveListener{ln.(*net.TCPListener)}
			err = s.HttpServer.Serve(*listener)
			if !s.autoRestartAfterError(err) {
				break
			}
		}
		done <- err
	}

	listenAndRunSSL := func(listener *net.Listener, port string, done chan error) {
		var err error
		for {
			var ln net.Listener
			if ln, err = s.createSSLListener(port); err != nil {
				s.errorLog.Errorf("createSSLListener error: %s\n", err.Error())
				break
			}
			*listener = ln
			err = s.HttpServer.Serve(*listener)
			if !s.autoRestartAfterError(err) {
				break
			}
		}
		done <- err
	}

	// PROBLEM: if one of these listeners errors out, then we won't know it until all other listeners
	// have finished too. We need a different model here, like a polling loop, instead of sequential code.
	listenAndRunHttpBridge := func(done chan error) {
		done <- s.runHttpBridgeServers()
	}

	var donePrimary, doneSecondary, doneSSL, doneHttpBridge chan error
	donePrimary = make(chan error)
	go listenAndRunHTTP(&s.listener, httpPort, donePrimary)
	if httpPortSecondary != "" {
		doneSecondary = make(chan error)
		go listenAndRunHTTP(&s.listenerSecondary, httpPortSecondary, doneSecondary)
	}
	if sslPort != "" {
		doneSSL = make(chan error)
		go listenAndRunSSL(&s.listenerSSL, sslPort, doneSSL)
	}
	doneHttpBridge = make(chan error)
	go listenAndRunHttpBridge(doneHttpBridge)

	// Wait for all potential listeners to finish
	err := []error{}
	if donePrimary != nil {
		err = append(err, <-donePrimary)
	}
	if doneSecondary != nil {
		err = append(err, <-doneSecondary)
	}
	if doneSSL != nil {
		err = append(err, <-doneSSL)
	}
	if doneHttpBridge != nil {
		err = append(err, <-doneHttpBridge)
	}
	if len(err) == 0 {
		return errors.New("Server not configured to listen on any ports")
	}
	// Return the first non-nil error
	for _, e := range err {
		if e != nil {
			return e
		}
	}
	return nil
}

func pickLogfile(logfile string) string {
	if logfile != "" {
		return logfile
	}
	return log.Stdout
}

func (s *Server) autoRestartAfterError(err error) bool {
	if err == nil {
		// Is this really the right thing to do? I don't know anymore... [BMH 2015-03-06]
		return true
	}
	if strings.Contains(err.Error(), "specified network name is no longer available") {
		s.errorLog.Warnf("Automatically restarting after receiving error 64")
		return true
	}
	return false
}

func (s *Server) createSSLListener(port string) (net.Listener, error) {
	// This function was modelled on the code inside the standard library's ListenAndServeTLS()

	config := &tls.Config{}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	if _, err := tls.LoadX509KeyPair(s.configHttp.CertFile, s.configHttp.CertKeyFile); err != nil {
		return nil, fmt.Errorf("Error reading cert %v: %v", s.configHttp.CertFile, err)
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(s.configHttp.CertFile, s.configHttp.CertKeyFile)
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", port)
	if err != nil {
		return nil, err
	}

	return tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config), nil
}

// Detect illegal requests
func (s *Server) isLegalRequest(req *http.Request) bool {
	// We were getting a whole lot of requests to the 'telco' server where the hostname was "yahoo.mail.com".
	if req.URL.Host == "yahoo.mail.com" {
		s.errorLog.Errorf("Illegal hostname (%s) - closing connection", req.URL.Host)
		return false
	}
	return true
}

/*
ServeHTTP is the single router access point to the frontdoor server. All request are handled in this method.
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
	newurl, requirePermission, passThroughAuth := s.translator.processRoute(req.URL)

	if s.debugRoutes {
		s.errorLog.Infof("(%v) -> (%v)", req.RequestURI, newurl)
	}

	if newurl == "" {
		http.Error(w, "Route not found", http.StatusNotFound)
		return
	}

	authData, authOK := s.authorize(w, req, requirePermission)
	if !authOK {
		return
	}

	if !authPassThrough(s.errorLog, w, req, authData, passThroughAuth) {
		return
	}

	switch parse_scheme(newurl) {
	case scheme_http:
		fallthrough
	case scheme_https:
		s.forwardHttp(w, req, newurl)
	case scheme_httpbridge:
		s.forwardHttpBridge(w, req, newurl)
	case scheme_ws:
		s.forwardWebsocket(w, req, newurl)
	default:
		s.errorLog.Errorf("Unrecognized scheme (%v) -> (%v)", req.RequestURI, newurl)
		http.Error(w, "Unrecognized forwarding URL", http.StatusInternalServerError)
	}
}

/*
forwardHTTP connects to all http scheme backends and copies bidirectionaly between the incoming
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
		s.errorLog.Info("HTTP RoundTrip error: " + err.Error())
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
		copyHeaders(req.Header, config.Header)
		if errCfg != nil {
			s.errorLog.Errorf("Error with config: %v\n", errCfg)
			return
		}
		backend, errOpen := websocket.DialConfig(config)
		if errOpen != nil {
			s.errorLog.Errorf("Error with websocket.DialConfig: %v\n", errOpen)
			return
		}
		copy := func(fromSocket *websocket.Conn, toSocket *websocket.Conn, toBackend bool, done chan bool) {

			for {
				var data string
				var err error
				err = websocket.Message.Receive(fromSocket, &data)
				if err == io.EOF {
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

func (s *Server) forwardHttpBridge(w http.ResponseWriter, req *http.Request, newurl string) {
	parsed, _ := url.Parse(newurl)
	port, _ := strconv.Atoi(parsed.Host)
	s.httpBridgeServers[port].ServeHTTP(w, req)
}

// Returns true if the request should continue to be passed through the router
// We make a round-trip to imqsauth here to check the credentials of the incoming request.
// This adds about a 0.5ms latency to the request. It might be worthwhile to embed
// imqsauth inside imqsrouter.
func (s *Server) authorize(w http.ResponseWriter, req *http.Request, requirePermission string) (authData *serviceauth.ImqsAuthResponse, authOK bool) {
	if requirePermission == "" {
		return nil, true
	}

	if err := serviceauth.VerifyInterServiceRequest(req); err == nil {
		return nil, true
	}

	if httpCode, errorMsg, authData := serviceauth.VerifyUserHasPermission(req, requirePermission); httpCode == http.StatusOK {
		return authData, true
	} else { // Not OK
		if httpCode == http.StatusUnauthorized {
			s.errorLog.Info(errorMsg) // we expect some unauthorized requests, so don't log them as errors
		} else {
			s.errorLog.Error(errorMsg)
		}
		http.Error(w, errorMsg, httpCode)
		return nil, false
	}
}

func (s *Server) Stop() {
	s.errorLog.Info("Shutting down")
	if s.listener != nil {
		s.listener.Close()
	}

	if s.listenerSecondary != nil {
		s.listenerSecondary.Close()
	}

	if s.listenerSSL != nil {
		s.listenerSSL.Close()
	}
	for _, v := range s.httpBridgeServers {
		v.Stop()
	}
	s.waiter.Wait()
}

// Start HttpBridge listeners on all the ports that are configured.
// It doesn't make sense to delay this process until the first incoming request for a particular
// backend, since HttpBridge backends will constantly be trying to connect to us, and
// probably emitting warnings to their logs if they are unable to connect.
func (s *Server) runHttpBridgeServers() error {
	done := make(chan error)
	nwaiting := 0
	for _, v := range s.translator.allRoutes() {
		if v.scheme() != scheme_httpbridge {
			continue
		}
		parsed, err := url.Parse(v.target.baseUrl)
		if err != nil {
			return fmt.Errorf(`Invalid URL "%v": %v`, v.target.baseUrl, err)
		}
		port, _ := strconv.Atoi(parsed.Host)
		if port < 1 || port > 65535 {
			return fmt.Errorf(`Invalid port specification in httpbridge URL "%v"`, v.target.baseUrl)
		}
		if s.httpBridgeServers[port] != nil {
			continue
		}
		hs := &httpbridge.Server{
			DisableHttpListener: true,
			BackendPort:         fmt.Sprintf(":%v", port),
		}
		hs.Log.Target = s.errorLog
		hs.Log.Level = makeHttpBridgeLogLevel(s.errorLog.Level)
		s.httpBridgeServers[port] = hs
		go func() {
			nwaiting++
			done <- hs.ListenAndServe()
		}()
	}
	var firstErr error
	for nwaiting != 0 {
		err := <-done
		nwaiting--
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func makeHttpBridgeLogLevel(l log.Level) httpbridge.LogLevel {
	switch l {
	case log.Trace:
		return httpbridge.LogLevelDebug
	case log.Debug:
		return httpbridge.LogLevelDebug
	case log.Info:
		return httpbridge.LogLevelInfo
	case log.Warn:
		return httpbridge.LogLevelWarn
	case log.Error:
		return httpbridge.LogLevelError
	}
	return httpbridge.LogLevelDebug
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

//copy all headers from src to dst
func copyHeaders(src http.Header, dst http.Header) {
	for k, vv := range src {
		for _, v := range vv {
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

// This is copied from the standard library.
// See that for reference.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

func init() {
}
