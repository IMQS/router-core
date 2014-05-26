package router

import (
	"code.google.com/p/go.net/websocket"
	"flag"
	"github.com/cespare/go-apachelog"
	"io"
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

/*
Server used for serving at the router.
*/
type Server struct {
	HttpServer    *http.Server
	httpTransport *http.Transport
	router        Router
	listener      net.Listener
	waiter        sync.WaitGroup
	filechecker   *regexp.Regexp
	proxy         *string
}

// NewServer creates a new server instance; starting up logging and creating a routing instance.
func NewServer(config *RouterConfig, flags *flag.FlagSet) (*Server, error) {
	file, err := os.OpenFile(flags.Lookup("accesslog").Value.String(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.ModePerm)
	if err != nil {
		return nil, err
	}
	s := &Server{}
	s.HttpServer = &http.Server{}
	s.HttpServer.Handler = apachelog.NewHandler(s, file)

	dka, err := strconv.ParseBool(flags.Lookup("disablekeepalive").Value.String())
	if err != nil {
		return nil, err
	}
	mic, err := strconv.ParseUint(flags.Lookup("maxidleconnections").Value.String(), 0, 8)
	if err != nil {
		return nil, err
	}
	rht, err := strconv.ParseUint(flags.Lookup("responseheadertimeout").Value.String(), 0, 8)
	if err != nil {
		return nil, err
	}

	s.httpTransport = &http.Transport{
		DisableKeepAlives:     dka,
		MaxIdleConnsPerHost:   int(mic),
		DisableCompression:    true,
		ResponseHeaderTimeout: time.Second * time.Duration(rht),
	}

	if s.router, err = NewRouter(config); err != nil {
		return nil, err
	}
	if file, err = os.OpenFile(flags.Lookup("errorlog").Value.String(),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.ModePerm); err != nil {
		return nil, err
	}
	log.SetOutput(file)
	log.Println("Starting v0.02 with:")
	log.Println("\tDisableKeepAlives:", flags.Lookup("disablekeepalive").Value.String())
	log.Println("\tMaxIdleConnsPerHost:", flags.Lookup("maxidleconnections").Value.String())
	log.Println("\tResponseHeaderTimeout:", flags.Lookup("responseheadertimeout").Value.String())
	s.filechecker = regexp.MustCompile(`([^/]\w+)\.(wsdl)$`)
	proxy := flags.Lookup("proxy").Value.String()
	if len(proxy) > 0 {
		s.proxy = &proxy
	}
	log.Println("\tproxy:", proxy)
	return s, nil
}

// Run the server
func (s *Server) ListenAndServe() error {
	addr := s.HttpServer.Addr
	if addr == "" {
		addr = ":http"
	}
	var err error
	for {
		if s.listener, err = net.Listen("tcp", addr); err != nil {
			log.Printf("In Listen error : %s\n", err.Error())
			return err
		}
		err = s.HttpServer.Serve(s.listener)
		if err != nil {
			if strings.Contains(err.Error(), "specified network name is no longer available") {
				log.Println("Restarting Error 64")
			} else {
				break
			}
		}
	}
	return err
}

/*
ServeHTTP is the single router access point to the frondoor server. All request are handled in this method.
 It uses Routes to generate the new url and then switches on scheme type to connect to the backend copying
between these pipes.
*/
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.waiter.Add(1)
	defer s.waiter.Done()
	// Catch wsdl here to statically serve.
	// Will be exanded to serve static files.
	filename := s.filechecker.FindString(req.RequestURI)
	if filename != "" {
		http.ServeFile(w, req, "C:\\imqsbin\\conf\\"+filename)
		return
	}
	newurl, scheme, proxy, routed := s.router.ProcessRoute(req)
	log.Printf("%s %s %s %s", req.RequestURI, newurl, scheme, proxy)
	if !routed {
		// Everything not routed is a NotFound "error"
		http.Error(w, "Route not found", http.StatusNotFound)
		return
	}
	switch scheme {
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
		// check for override
		var proxystr string
		if s.proxy != nil {
			proxystr = *s.proxy
		} else {
			proxystr = proxy
		}
		proxyurl, err := url.Parse("http://" + proxystr)
		if err != nil {
			log.Printf("Could not parse proxy")
		}
		s.httpTransport.Proxy = http.ProxyURL(proxyurl)
		log.Println("Using Proxy:", s.httpTransport.Proxy)
	} else {
		s.httpTransport.Proxy = nil
	}
	resp, e := s.httpTransport.RoundTrip(cleaned)
	if e != nil {
		log.Println("HTTP RoundTrip error: " + e.Error())
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
			log.Printf("Error with config: %v\n", errCfg.Error())
			return
		}
		backend, errOpen := websocket.DialConfig(config)
		if errOpen != nil {
			log.Printf("Error with websocket.DialConfig: %v\n", errOpen.Error())
			return
		}
		copy := func(fromSocket *websocket.Conn, toSocket *websocket.Conn, toBackend bool, done chan bool) {

			for {
				var data string
				var err error
				err = websocket.Message.Receive(fromSocket, &data)
				if err == io.EOF {
					log.Printf("Closing connection. EOF")
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

func (s *Server) Stop() {
	log.Println("Shutting down...")
	if s.listener != nil {
		s.listener.Close()
	}
	s.waiter.Wait()
}
