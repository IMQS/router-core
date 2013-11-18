/*
Package frontdoor provides proxy functionality for http and websockets.
This file provides the server functionality listening and routing the request to the various backends.
It further provides logging capabilities in the format of apache logs by the use of the github.com/cespare/go-apachelog package.
*/
package frontdoor

import (
	"code.google.com/p/go.net/websocket"
	"github.com/cespare/go-apachelog"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

/*
Server used for serving at the frontdoor.
*/
type Server struct {
	HttpServer *http.Server
	httpClient *http.Client
	routes     *Routes
	listener   net.Listener
	waiter sync.WaitGroup
}

/*
NewServer creates a new server instance; starting up logging and creating a routing instance.
*/
func NewServer(configfilename string) *Server {
	file, err := os.OpenFile("c:\\imqsvar\\logs\\frontdoor.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	s := &Server{}
	s.HttpServer = &http.Server{}
	s.HttpServer.Handler = apachelog.NewHandler(s, file)

	httpTransport := &http.Transport{
		DisableCompression:    true,
		ResponseHeaderTimeout: time.Second * 5,
	}
	s.httpClient = &http.Client{
		Transport: httpTransport,
	}
	s.routes = NewRoutes(configfilename)
	return s
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
ServeHTTP is the single frontdoor access point to the frondoor server. All request are handled in this method.
It uses Routes to generate the new url and then switches on scheme type to connect to the backend copying
between these pipes.
*/
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.waiter.Add(1)
	defer s.waiter.Done()
	newurl, scheme, routed := s.routes.Route(req)
	switch scheme {
	case "http":
		if routed {
			s.forwardHttp(w, req, newurl)
		} else {
			// Placeholder for static content handler
		}
	case "ws":
		s.forwardWebsocket(w, req, newurl)
	}
}

/*
forwardHTTP connects to all http scheme backends and copies bidirectionaly between the incomming
connections and the backend connections. It also copies to required HTTP headers between the connections making the frontdoor "middle man" invisible to incomming connections.
The body part of both requests and responses are implemented as Readers, thus allowing the body contents
to be copied directly down the sockets, negating the requirement to have a buffer here. This allows all
http bodies, i.e. chunked, to pass through.
*/
func (s *Server) forwardHttp(w http.ResponseWriter, req *http.Request, newurl string) {
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

	resp, e := s.httpClient.Do(cleaned)
	if e != nil {
		http.Error(w, e.Error(), http.StatusGatewayTimeout)
	} else {
		copyheaders(resp.Header, w.Header())
		w.WriteHeader(resp.StatusCode)

		if resp.Body != nil {
			writers := make([]io.Writer, 0, 1)
			writers = append(writers, w)
			io.Copy(io.MultiWriter(writers...), resp.Body)
		}

		resp.Body.Close()

	}
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
				if e := websocket.Message.Receive(fromSocket, &msg); e != nil {
					//fmt.Printf("Closing connection. Error on fromSocket.Receive (%v)\n", e)
					break
				}
				if e := websocket.Message.Send(toSocket, msg); e != nil {
					//fmt.Printf("Closing connection. Error on toSocket.Send (%v)\n", e)
					break
				}
			}
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
	s.listener.Close()
	s.waiter.Wait()
}
