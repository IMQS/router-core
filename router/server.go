package router

import (
	"compress/gzip"
	"fmt"
	"github.com/IMQS/go-apachelog" // Older, but supports websockets. Forked to include time zone in access logs.
	"io"
	"io/ioutil"
	golog "log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	// "github.com/cespare/hutil/apachelog" // Newer, but doesn't support websockets
	"github.com/IMQS/httpbridge/go/src/httpbridge"
	"github.com/IMQS/log"
	"github.com/IMQS/serviceauth"
	"github.com/IMQS/serviceconfigsgo"
	ms_http "github.com/MSOpenTech/azure-sdk-for-go/core/http"
	"golang.org/x/net/websocket"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Router Server
type Server struct {
	httpTransport     *ms_http.Transport // For talking to backend services
	configHttp        ConfigHTTP
	accessLogFile     string
	debugRoutes       bool // If enabled, dumps every translated route to the error log
	translator        urlTranslator
	errorLog          *log.Logger
	wsdlMatch         *regexp.Regexp             // hack for serving static content
	httpBridgeServers map[int]*httpbridge.Server // Keys of the map are httpbridge backend port numbers
	udpConnPool       *UDPConnectionPool
}

type frontServer struct {
	isSecure bool
	server   *Server
}

func (f *frontServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	f.server.ServeHTTP(f.isSecure, w, req)
}

// NewServer creates a new server instance; starting up logging and creating a routing instance.
func NewServer(config *Config) (*Server, error) {
	var err error
	s := &Server{}
	s.configHttp = config.HTTP
	s.httpBridgeServers = map[int]*httpbridge.Server{}
	s.udpConnPool = NewUDPConnectionPool()

	s.debugRoutes = config.DebugRoutes
	s.accessLogFile = config.AccessLog
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

	if err := serviceconfig.AddSystemVariableToConfigService("router_http_port", getRouterPort(s.configHttp.Port)); err != nil {
		return nil, err
	}

	s.errorLog.Info("Router starting with:")
	s.errorLog.Infof(" DisableKeepAlives: %v", config.HTTP.DisableKeepAlive)
	s.errorLog.Infof(" MaxIdleConnsPerHost: %v", config.HTTP.MaxIdleConnections)
	s.errorLog.Infof(" ResponseHeaderTimeout: %v", config.HTTP.ResponseHeaderTimeout)
	s.wsdlMatch = regexp.MustCompile(`([^/]\w+)\.(wsdl)$`)
	return s, nil
}

func getRouterPort(port uint16) string {
	if port == 0 {
		return "80"
	}
	return strconv.FormatUint(uint64(port), 10)
}

// Run the server.
// Returns the first error from the first listener that aborts.
func (s *Server) ListenAndServe() error {
	httpAddr := fmt.Sprintf(":%v", s.configHttp.GetPort())
	httpAddrSecondary := ""
	if s.configHttp.SecondaryPort != 0 {
		httpAddrSecondary = fmt.Sprintf(":%v", s.configHttp.SecondaryPort)
	}
	secureAddr := ""
	if s.configHttp.EnableHTTPS {
		secureAddr = ":https"
		if s.configHttp.HTTPSPort != 0 {
			secureAddr = fmt.Sprintf(":%v", s.configHttp.HTTPSPort)
		}
	}

	errors := make(chan error)

	accessLog := openLog(s.accessLogFile, os.Stdout)

	logForwarder := golog.New(log.NewForwarder(0, log.Info, s.errorLog), "", 0)

	runHttp := func(addr string, secure bool, errors chan error) {
		hs := &http.Server{}
		hs.Addr = addr
		hs.Handler = &frontServer{secure, s}
		hs.ErrorLog = logForwarder

		// Newer apachelog (see comments in package includes list)
		//hs.Handler = apachelog.NewHandler(`%h - %u %t "%r" %s %b %T`, s, accessLog)

		// Older apachelog
		hs.Handler = apachelog.NewHandler(hs.Handler, accessLog)

		var err error
		for {
			if secure {
				err = hs.ListenAndServeTLS(s.configHttp.CertFile, s.configHttp.CertKeyFile)
			} else {
				err = hs.ListenAndServe()
			}
			if !s.autoRestartAfterError(err) {
				break
			}
		}
		errors <- err
	}

	go runHttp(httpAddr, false, errors)
	if httpAddrSecondary != "" {
		go runHttp(httpAddrSecondary, false, errors)
	}
	if secureAddr != "" {
		go runHttp(secureAddr, true, errors)
	}
	go func() {
		errors <- s.runHttpBridgeServers()
	}()

	// Wait for the first non-nil error and return it
	for {
		err := <-errors
		if err != nil {
			s.errorLog.Infof(`Router exiting. First non-nil error was "%v"`, err)
			return err
		}
	}

	// unreachable
	return nil
}

func pickLogfile(logfile string) string {
	if logfile != "" {
		return logfile
	}
	return log.Stdout
}

// Certain benign errors seem to occur frequently, and we don't want to shut ourselves down when
// that happens. Instead, we just fire ourselves up again.
func (s *Server) autoRestartAfterError(err error) bool {
	if strings.Contains(err.Error(), "specified network name is no longer available") {
		s.errorLog.Warnf("Automatically restarting after receiving error 64")
		return true
	}
	return false
}

// Detect illegal requests
func (s *Server) isLegalRequest(req *http.Request) bool {
	// We were getting a whole lot of requests to the 'telco' server where the hostname was "yahoo.mail.com".
	// TODO: move this to blacklist config file
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
func (s *Server) ServeHTTP(isSecure bool, w http.ResponseWriter, req *http.Request) {
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

	// Redirect HTTP requests to HTTPS
	// Requests from IP addressses and localhost are left untouched
	if s.configHttp.RedirectHTTP && !isSecure && net.ParseIP(req.Host) == nil && req.Host != "localhost" {

		// Give 404 for appcache manifest request when HTTP redirection is enabled, this clears out old manifest
		if req.RequestURI == "/manifest.appcache" {
			http.Error(w, "", http.StatusNotFound)
			s.errorLog.Info("Appcache manifest cleared")
			return
		}

		// Only request to the root of the domain will get redirected, all other requests remain untouched, for instance
		// http://demo.imqs.co.za will get redirected, but http://demo.imqs.co.za/index.html won't
		if req.RequestURI == "/" || req.RequestURI == "" {
			host := strings.Split(req.Host, ":")[0] // remove port from host, this is safe even when no port is specified
			target := fmt.Sprintf("https://%s%s", host, req.URL.Path)
			if s.configHttp.HTTPSPort != 0 {
				target = fmt.Sprintf("https://%s:%d%s", host, s.configHttp.HTTPSPort, req.URL.Path) // override default HTTPS port
			}
			if len(req.URL.RawQuery) > 0 {
				target += "?" + req.URL.RawQuery
			}
			w.Header().Set("cache-control", "no-store")
			s.errorLog.Infof("Redirecting request from %s to %s \n", req.URL.String(), target)
			http.Redirect(w, req, target, http.StatusMovedPermanently)
			return
		}
	}

	// Catch ping requests
	if req.RequestURI == "/router/ping" {
		s.Pong(w, req)
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
		s.forwardHttpBridge(isSecure, w, req, newurl)
	case scheme_ws:
		s.forwardWebsocket(w, req, newurl)
	case scheme_udp:
		s.forwardUDP(w, req, newurl)
	default:
		s.errorLog.Errorf("Unrecognized scheme (%v) -> (%v)", req.RequestURI, newurl)
		http.Error(w, "Unrecognized forwarding URL", http.StatusInternalServerError)
	}
}

/*
forwardHTTP connects to all http scheme backends and copies bidirectionally between the incoming
connections and the backend connections. It also copies required HTTP headers between the connections making the
router "middle man" invisible to incoming connections.
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
		return
	}

	srcHost := req.Host     // Client address.
	dstHost := cleaned.Host // Destination address, e.g. 127.0.0.1:5984.

	// Copy headers from client req into cleaned req, replacing Location header value if found.
	copyheadersIn(srcHost, req.Header, dstHost, cleaned.Header)
	cleaned.Proto = req.Proto
	cleaned.ContentLength = req.ContentLength

	resp, err := s.httpTransport.RoundTrip(cleaned)
	if err != nil {
		s.errorLog.Info("HTTP RoundTrip error: " + err.Error())
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return
	}

	var responseWriter io.Writer = w
	if resp.Body != nil {

		// Only compress when it hasn't been already and the client supports it.
		if resp.Header.Get("Content-Encoding") == "" && strings.Contains(req.Header.Get("Accept-Encoding"), "gzip") {

			// Remove any possible metadata in the header value, e.g. "text/html; charset=utf-8" becomes "text/html".
			responseContentType := resp.Header.Get("Content-Type")
			var trimmedContentType string
			sepIdx := strings.Index(responseContentType, ";")
			if sepIdx > 0 {
				trimmedContentType = responseContentType[:sepIdx]
			} else {
				trimmedContentType = responseContentType
			}

			// Only compress when content type is known and whitelisted.
			if _, allowed := s.configHttp.AutomaticGzip.whitelistMap[trimmedContentType]; allowed {
				// If we compress a response that is not chunked, then the original content length header is invalid.
				// We also do not know what the final length of the compressed content will be,
				// unless we zip to a buffer first and then write that to the response.
				// But we want to avoid a buffer for performance reasons.
				// It seems either the Go runtime or browser calculates and inserts the header automatically
				// at some point, so we just delete it here.
				resp.Header.Del("Content-Length")

				zipper := gzip.NewWriter(w)
				defer zipper.Close()
				responseWriter = zipper

				if resp.Header.Get("Vary") == "" {
					resp.Header.Add("Vary", "Accept-Encoding")
				}
				resp.Header.Set("Content-Encoding", "gzip")
			}
		}
	}

	// Copy headers from response into w, replacing Location header value back to original if found.
	copyheadersOut(dstHost, resp.Header, srcHost, w.Header(), req.TLS != nil)
	w.WriteHeader(resp.StatusCode)

	if resp.Body != nil {
		defer resp.Body.Close()
		io.Copy(responseWriter, resp.Body)
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

/*
forwardUDP does for UDP what forwardHTTP does for http requests. UDP is connectionless, so implementation is very simple
*/
func (s *Server) forwardUDP(w http.ResponseWriter, req *http.Request, newurl string) {
	u, err := url.Parse(newurl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dstHost := u.Host // Destination address, e.g. 127.0.0.1:5984.
	msg, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = s.udpConnPool.Send(dstHost, msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Server) forwardHttpBridge(isSecure bool, w http.ResponseWriter, req *http.Request, newurl string) {
	// An example mapping from original URL to newurl is
	// http://localhost/map2/hello/foo -> httpbridge://2019/hello/foo
	// The 'httpbridge' portion of newurl is not interesting to us. It is merely syntax
	// of the routing table, to make it crystal clear that the backend is not another
	// HTTP hop, but an httpbridge server.
	// In order to be useful, we need to replace the 'httpbridge' portion of newurl
	// with something that looks like an http URL.
	//
	// In summary, the URL undergoes the following three stages
	//
	//   https://example.imqs.co.za/map2/hello/foo   (original)
	//   httpbridge://2019/hello/foo                 (transformed by routing table, notice that map2 prefix was removed)
	//   https://example.imqs.co.za/hello/foo        (rewritten to be http-like. Basically, just routing table prefix is removed)
	//
	// Note that we only send httpbridge the part after the hostname, so in the above example,
	// httpbridge only receives "/hello/foo". If we want to transmit the other information,
	// then we'll add that information to headers, or to the flatbuffer.

	// If you need to build a "X-Forward-For" header, then you can form it by doing: cleaned_prefix + req.RequestURI
	//  	cleaned_prefix := ""
	//  	if isSecure {
	//  		cleaned_prefix = "https://"
	//  	} else {
	//  		cleaned_prefix = "http://"
	//  	}
	//  	cleaned_prefix += req.Host

	//fmt.Printf("newurl: %v\n", newurl)
	parsed, _ := url.Parse(newurl)
	port, _ := strconv.Atoi(parsed.Host)
	cleaned_uri := parsed.Path
	if len(parsed.RawQuery) != 0 {
		cleaned_uri += "?" + parsed.RawQuery
	}
	//fmt.Printf("org path = %v, cleaned_prefix = %v, cleaned_uri = %v, port = %v\n", req.RequestURI, cleaned_prefix, cleaned_uri, port)

	// I originally thought that RawPath was the right thing to use here, but it turns out that url.Parse/url.ParseRequestURI will only set
	// RawPath if EscapedPath() is different from RawPath. This header was originally added for our request signing system, so that
	// the receiver can get access to the original URL string, the way the sender composed it. It looks like the best way to do that
	// is to parse the RequestURI ourselves, by looking for the ? and just using everything before that.
	rawPath := req.RequestURI
	if question := strings.IndexRune(req.RequestURI, '?'); question != -1 {
		rawPath = req.RequestURI[:question]
	}
	//fmt.Printf("%v\n", rawPath)
	req.Header.Add("X-Original-Path", rawPath)

	// httpbridge doesn't care about req.URL - it only looks at RequestURI
	req.RequestURI = cleaned_uri

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
		nwaiting++
		go func() {
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

func (s *Server) Pong(w http.ResponseWriter, req *http.Request) {
	timestamp := time.Now().Unix()
	fmt.Fprintf(w, `{"Timestamp":%v}`, timestamp)
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
				// need to rewrite it to be an external address. It may be wiser to just strip the absolute portion of Location away,
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
