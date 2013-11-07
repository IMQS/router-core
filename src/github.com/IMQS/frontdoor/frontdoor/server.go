package frontdoor

import (
	"code.google.com/p/go.net/websocket"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	HttpServer *http.Server

	httpClient *http.Client
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

	return s
}

func (s *Server) ListenAndServe() {
	s.HttpServer.ListenAndServe()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("URL Path = %v\n", req.URL.Path)
	//w.WriteHeader(http.StatusOK)
	//response.Header().Set("key", value)
	if strings.Index(req.URL.Path, "/ws") == 0 {
		s.forwardWebsocket(w, req)
	} else if strings.Index(req.URL.Path, "/") == 0 {
		s.forwardHttp(w, req)
	} else {
		http.Error(w, "Unknown backend", http.StatusNotFound)
	}
}

func (s *Server) forwardHttp(w http.ResponseWriter, req *http.Request) {
	useStatic := true
	if useStatic {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(myHtml))

	} else {
		fullURI := "http://localhost:80" + req.RequestURI[5:]
		//fmt.Printf("fullURI: %v\n", fullURI)
		cleaned, err := http.NewRequest(req.Method, fullURI, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		for _, cookie := range req.Cookies() {
			cleaned.AddCookie(cookie)
		}
		cleaned.Proto = req.Proto
		cleaned.Host = req.Host
		// httpClient does not allow RequestURI to be set
		//req.RequestURI = ""
		resp, e := s.httpClient.Do(cleaned)
		if e != nil {
			http.Error(w, e.Error(), http.StatusGatewayTimeout)
		} else {
			resp.Write(w)
		}
	}
}

func (s *Server) forwardWebsocket(w http.ResponseWriter, req *http.Request) {

	fmt.Printf("Opening websocket: %v %v\n", req.Method, req.RequestURI)

	myHandler := func(con *websocket.Conn) {
		fmt.Printf("Inside myhandler\n")
		fullURI := "ws://localhost:8081/ws"
		origin := "http://localhost:8080"
		config, errCfg := websocket.NewConfig(fullURI, origin)
		if errCfg != nil {
			fmt.Printf("Error with config: %v\n", errCfg.Error())
			return
		}
		backend, errOpen := websocket.DialConfig(config)
		if errOpen != nil {
			fmt.Printf("Error with websocket.DialConfig: %v\n", errOpen.Error())
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
					fmt.Printf("Closing connection. Error on fromSocket.Receive (%v)\n", e)
					break
				}
				if e := websocket.Message.Send(toSocket, msg); e != nil {
					fmt.Printf("Closing connection. Error on toSocket.Send (%v)\n", e)
					break
				}
			}
			done <- true
		}
		finished := make(chan bool)
		go copy(con, backend, finished)
		go copy(backend, con, finished)
		<-finished
		fmt.Printf("Closing websocket\n")
	}

	wsServer := &websocket.Server{}
	wsServer.Handler = myHandler
	wsServer.ServeHTTP(w, req)
	fmt.Printf("wsHandler.ServeHTTP returned\n")
}

const myHtml = `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
</head>

<body>
</body>

<script>

var numSockets = 1;

function runSocket() {
	var ws = new WebSocket("ws://localhost:8080/ws");
	var isOpen = false;
	var nMsg = 0;
	var repeat = function() {
		if ( !isOpen )
			return;
		nMsg++;
		var data = "The date is " + (new Date()).getTime();
		console.log("Sending '" + data + "' to websocket");
		ws.send(data);
		if ( nMsg > 3 ) {
			console.log("Closing after 3 messages\n");
			ws.close();
		}
		else
			setTimeout(repeat, 1);
	}

	ws.onopen = function() {
		isOpen = true;
		console.log("open");
		repeat();
	}
	ws.onmessage = function(e) {
		console.log("data in: " + e.data);
	};
	ws.onclose = function() {
		isOpen = false;
		console.log("closed");
	};
}

for (var isock = 0; isock < numSockets; isock++)
	runSocket();

</script>
</html>
`
