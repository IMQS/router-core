//Package frontdoor provides proxy functionality for http and websockets.
package frontdoor

import (
	"code.google.com/p/go.net/websocket"
	"io"
	"net/http"
	"time"
)

type Writer func(*http.Response) (io.WriteCloser, error)

type Server struct {
	HttpServer *http.Server
	httpClient *http.Client
	routes     *Routes
//	writers    []Writer
}

func NewServer() *Server {
	s := &Server{}
	s.HttpServer = &http.Server{}
	s.HttpServer.Handler = s

	httpTransport := &http.Transport{
		DisableCompression:    true,
		ResponseHeaderTimeout: time.Second * 5,
	}
	s.httpClient = &http.Client{
		Transport: httpTransport,
	}
	s.routes = NewRoutes()
	return s
}

func (s *Server) ListenAndServe() {
	s.HttpServer.ListenAndServe()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	newurl, scheme := s.routes.Route(req)
	//fmt.Printf("\n\n New URL : %s\n\n",newurl)
	switch scheme {
	case "http":
		s.forwardHttp(w, req, newurl)
	case "ws":
		s.forwardWebsocket(w, req, newurl)
	}
}

func (s *Server) forwardHttp(w http.ResponseWriter, req *http.Request, newurl string) {
	//PrintRequest(req, "Original Request")
	cleaned, err := http.NewRequest(req.Method, newurl, req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	//PrintRequest(cleaned, "New Clean Request")

	copyheaders := func(src http.Header, dst http.Header) {
		for k, vv := range src {
			for _, v := range vv {
				dst.Add(k, v)
			}
		}
	}

	copyheaders(req.Header, cleaned.Header)
	//cleaned.Header.Add("Host", cleaned.Host)
	cleaned.Proto = req.Proto
	//cleaned.Host = req.Host
	cleaned.ContentLength = req.ContentLength

	//PrintRequest(cleaned, "Cleaned Request")

	// httpClient does not allow RequestURI to be set
	//req.RequestURI = ""
	resp, e := s.httpClient.Do(cleaned)
	if e != nil {
		http.Error(w, e.Error(), http.StatusGatewayTimeout)
	} else {
		//resp.Write(w)
		//PrintResponse(resp, "Actual Response")
		copyheaders(resp.Header, w.Header())
		w.WriteHeader(resp.StatusCode)
		
		//wclosers := make([]io.WriteCloser, 0, 0)

		//for i, _ := range s.writers {
		//	wcloser, err := s.writers[i](resp)
		//	if wcloser != nil {
		//		wclosers = append(wclosers, wcloser)
		//	}
		//	if err != nil {
		//		log.Panic(err)
		//	}
		//}

		if resp.Body != nil {
			writers := make([]io.Writer, 0, 1)
			writers = append(writers, w)
			//for i, _ := range wclosers {
			//	writers = append(writers, wclosers[i])
			//}
			io.Copy(io.MultiWriter(writers...), resp.Body)
		}

		// Closing response.
		resp.Body.Close()

	}
}

func (s *Server) forwardWebsocket(w http.ResponseWriter, req *http.Request, newurl string) {

	//fmt.Printf("Opening websocket: %v %v\n", req.Method, req.RequestURI)

	myHandler := func(con *websocket.Conn) {
		//fmt.Printf("Inside myhandler\n")
		//fullURI := "ws://localhost:8081/ws"
		origin := "http://localhost:8080"
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
				/*
					// This approach causes the socket to never get closed.
					if _, e := io.Copy(toSocket, fromSocket); e != nil {
						fmt.Printf("Closing connection. Error on io.Copy (%v)", e)
						break
					}
				*/
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
		//fmt.Printf("Closing websocket\n")
	}

	wsServer := &websocket.Server{}
	wsServer.Handler = myHandler
	wsServer.ServeHTTP(w, req)
	//fmt.Printf("wsHandler.ServeHTTP returned\n")
}
