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
	proxy       *string
}

/*
NewServer creates a new server instance; starting up logging and creating a routing instance.
*/
func NewServer(config *RouterConfig, flags *flag.FlagSet) (*Server, error) {
	file, err := os.OpenFile(flags.Lookup("accesslog").Value.String(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.ModePerm)
	if err != nil {
		return nil, err
	}
	s := &Server{}
	s.HttpServer = &http.Server{}
	s.HttpServer.Handler = apachelog.NewHandler(s, file)
	var httpTransport *http.Transport

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

	httpTransport = &http.Transport{
		DisableKeepAlives:     dka,
		MaxIdleConnsPerHost:   int(mic),
		DisableCompression:    true,
		ResponseHeaderTimeout: time.Second * time.Duration(rht),
	}
	s.httpClient = &http.Client{
		Transport: httpTransport,
	}
	if s.router, err = NewRouter(config); err != nil {
		return nil, err
	}
	if file, err = os.OpenFile(flags.Lookup("errorlog").Value.String(),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.ModePerm); err != nil {
		return nil, err
	}
	log.SetOutput(file)
	log.Println("Starting v0.01 with:")
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

// This attempts to find the proxy configuration for this machine from the registry.
// This does not seem to work without elevated rights - will leave it here until solution is found.
//func findProxy() (proxy *string, err error) {
//	path, err := exec.LookPath("reg")
//	if err != nil {
//		return nil, err
//	}
//	out, err := exec.Command(path, "query", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyEnable").Output()
//	if err != nil {
//		return nil, err
//	}
//	if strings.Contains(string(out[:]), "0x0") {
//		return nil, nil
//	}
//	out, err = exec.Command(path, "query", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyServer").Output()
//	vals := strings.Split(string(out[:]), " ")
//	proxystr := strings.TrimSpace(vals[len(vals)-1])
//	proxy = &proxystr
//	return proxy, nil
//}

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
		actTransport.Proxy = http.ProxyURL(proxyurl)
		log.Println("Using Proxy:", actTransport.Proxy)
	} else {
		actTransport.Proxy = nil
	}
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
	if s.listener != nil {
		s.listener.Close()
	}
	s.waiter.Wait()
}
