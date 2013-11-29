package router

import (
	"code.google.com/p/go.net/websocket"
	"github.com/cespare/go-apachelog"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"
)

var connCount int = 0

/*
Server used for serving at the router.
*/
type Server struct {
	HttpServer  *http.Server
	httpClient  *http.Client
	router      Router
	listener    net.Listener
	waiter      sync.WaitGroup
	filechecker *regexp.Regexp
}

/*
NewServer creates a new server instance; starting up logging and creating a routing instance.
*/
func NewServer(configfilename string) (*Server, error) {
	file, err := os.OpenFile("c:\\imqsvar\\logs\\router.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.ModePerm)
	if err != nil {
		return nil, err
	}
	s := &Server{}
	s.HttpServer = &http.Server{}
	s.HttpServer.Handler = apachelog.NewHandler(s, file)

	httpTransport := &http.Transport{
		DisableCompression:    true,
		ResponseHeaderTimeout: time.Second * 60,
	}
	s.httpClient = &http.Client{
		Transport: httpTransport,
	}
	s.router, err = NewRouter(configfilename)
	if err != nil {
		return nil, err
	}
	file, err = os.OpenFile("c:\\imqsvar\\logs\\router_server.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.ModePerm)
	if err != nil {
		return nil, err
	}
	log.SetOutput(file)
	s.filechecker = regexp.MustCompile(`([^/]\w+)\.(wsdl)$`)
	return s, nil
}

/*
ListenAndServe exposes the embedded HttpServer method.
*/
func (s *Server) ListenAndServe() {
	addr := s.HttpServer.Addr
	if addr == "" {
		addr = ":http"
	}
	var err error
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	s.HttpServer.Serve(s.listener)
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
	newurl, scheme, proxy, routed := s.router.Route(req)
	log.Printf("%s %s %s %s", req.RequestURI, newurl, scheme, proxy)
	if !routed {
		// Everything not routed is a NotFound "error"
		http.Error(w, "Not Found", http.StatusNotFound)
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
*/
func (s *Server) forwardHttp(w http.ResponseWriter, req *http.Request, newurl, proxy string) {
	cleaned, err := http.NewRequest(req.Method, newurl, req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	copyheaders := func(src http.Header, dst http.Header) {
		for k, vv := range src {
			for _, v := range vv {
				dst.Add(k, v)
			}
		}
	}

	copyheaders(req.Header, cleaned.Header)
	cleaned.Proto = req.Proto
	cleaned.ContentLength = req.ContentLength
	actTransport := s.httpClient.Transport.(*http.Transport)
	actTransport.CloseIdleConnections()
	if proxy != "" {
		proxyurl, err := url.Parse("http://" + proxy)
		if err != nil {
			log.Printf("Could not parse proxy")
		}
		actTransport.Proxy = http.ProxyURL(proxyurl)
	} else {
		actTransport.Proxy = nil
	}
	log.Println(actTransport.Proxy)
	resp, e := s.httpClient.Do(cleaned)
	if e != nil {
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

	resp.Body.Close()

}

/*
forwardWebsocket does for websockets what forwardHTTP does for http requests. A new socket connection is made to the backend and messages are both ways.
*/
func (s *Server) forwardWebsocket(w http.ResponseWriter, req *http.Request, newurl string) {

	myHandler := func(con *websocket.Conn) {
		origin := "http://localhost"
		config, errCfg := websocket.NewConfig(newurl, origin)
		if errCfg != nil {
			//fmt.Printf("Error with config: %v\n", errCfg.Error())
			return
		}
		backend, errOpen := websocket.DialConfig(config)
		if errOpen != nil {
			//fmt.Printf("Error with websocket.DialConfig: %v\n", errOpen.Error())
			return
		}

		copy := func(fromSocket *websocket.Conn, toSocket *websocket.Conn, done chan bool) {
			for {
				var msg string
				if e := websocket.Message.Receive(fromSocket, &msg); e != nil && e != io.EOF {
					log.Printf("Closing connection. Error on fromSocket.Receive (%v)\n", e)
					break
				}
				if e := websocket.Message.Send(toSocket, msg); e != nil {
					log.Printf("Closing connection. Error on toSocket.Send (%v)\n", e)
					break
				}
			}
			log.Println(fromSocket)
			done <- true
		}
		finished := make(chan bool)
		go copy(con, backend, finished)
		go copy(backend, con, finished)
		<-finished
	}

	wsServer := &websocket.Server{}
	wsServer.Handler = myHandler
	wsServer.ServeHTTP(w, req)
}

func (s *Server) Stop() {
	log.Println("Shutting down...")
	s.listener.Close()
	s.waiter.Wait()
}
