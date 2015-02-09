package router

import (
	"github.com/cespare/go-apachelog"
	"github.com/natefinch/lumberjack"
	"golang.org/x/net/websocket"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Router Server
type Server struct {
	HttpServer        *http.Server
	httpTransport     *http.Transport
	router            Router
	errorLog          *log.Logger
	listener          net.Listener
	listenerSecondary net.Listener
	waiter            sync.WaitGroup
	wsdlMatch         *regexp.Regexp // hack for serving static content
}

// NewServer creates a new server instance; starting up logging and creating a routing instance.
func NewServer(config *Config) (*Server, error) {
	var err error
	s := &Server{}
	s.HttpServer = &http.Server{}
	s.HttpServer.Handler = apachelog.NewHandler(s, openLog(config.AccessLog, os.Stdout))

	logFlags := log.Ldate | log.Ltime | log.Lmicroseconds
	errorLog := openLog(config.ErrorLog, os.Stderr)
	s.errorLog = log.New(errorLog, "", logFlags)
	log.SetOutput(errorLog)
	log.SetFlags(logFlags)

	s.httpTransport = &http.Transport{
		DisableKeepAlives:     config.HTTP.DisableKeepAlive,
		MaxIdleConnsPerHost:   config.HTTP.MaxIdleConnections,
		DisableCompression:    true,
		ResponseHeaderTimeout: time.Second * time.Duration(config.HTTP.ResponseHeaderTimeout),
	}

	if s.router, err = NewRouter(config); err != nil {
		return nil, err
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
	newurl, proxy, routed := s.router.ProcessRoute(req)

	//s.errorLog.Printf("(%v) -> (%v) [%v]", req.RequestURI, newurl, proxy)

	if !routed {
		// Everything not routed is a NotFound "error"
		http.Error(w, "Route not found", http.StatusNotFound)
		return
	}
	switch parse_scheme(newurl) {
	case "http":
		s.forwardHttp(w, req, newurl, proxy)
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
func (s *Server) forwardHttp(w http.ResponseWriter, req *http.Request, newurl, proxy string) {
	cleaned, err := http.NewRequest(req.Method, newurl, req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	srcHost := req.Host
	dstHost := cleaned.Host

	copyheaders := func(src http.Header, dst http.Header) {
		for k, vv := range src {
			for _, v := range vv {
				if k == "Location" {
					v = strings.Replace(v, dstHost, srcHost, 1)
				}
				if k == "Connection" && v == "close" {
					// See detailed explanation in top-level function comment
					continue
				}
				dst.Add(k, v)
			}
		}
	}

	copyheaders(req.Header, cleaned.Header)
	cleaned.Proto = req.Proto
	cleaned.ContentLength = req.ContentLength

	if len(proxy) > 0 {
		proxyurl, err := url.Parse(proxy)
		if err != nil {
			s.errorLog.Printf("Could not parse proxy")
		}
		s.httpTransport.Proxy = http.ProxyURL(proxyurl)
		s.errorLog.Println("Using Proxy:", s.httpTransport.Proxy)
	} else {
		s.httpTransport.Proxy = nil
	}
	resp, e := s.httpTransport.RoundTrip(cleaned)
	if e != nil {
		s.errorLog.Println("HTTP RoundTrip error: " + e.Error())
		http.Error(w, e.Error(), http.StatusGatewayTimeout)
		return
	}
	defer resp.Body.Close()
	copyheaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)

	if resp.Body != nil {
		writers := make([]io.Writer, 0, 1)
		writers = append(writers, w)
		io.Copy(io.MultiWriter(writers...), resp.Body)
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
