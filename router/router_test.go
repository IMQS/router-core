package router

/*
In all tests the environment looks like the following :

 --------          --------             --------------
| client |  <-->  | router |  <------> | http backend |
 -------           --------             --------------
                      ^
                      |                 -------------------
                       --------------> | websocket backend |
                                        -------------------

Http:
Requests are send to the router which routes them to the backend and creates a response body
with the following format "METHOD <method> URL <backend received url> BODY <backend received body>",
this is then returned to the router which in turn returns it to client for checking.

Websocket:
Same as above but since there are no headers or methods in websockets the message received by the
backend are return to via the router to the client websocket.

An external request is also made and returned to the client which means that the test TestHostReplace
requires a working internet connection to pass.
*/

import (
	"fmt"
	"golang.org/x/net/websocket"
	"html"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const mainConfig = `
{
	"AccessLog":		"router-access-test.log",
	"ErrorLog":			"router-error-test.log",
	"Targets": {
		"PORT5000": {
			"URL": "http://127.0.0.1:5000"
		}
	},
	"Routes": {
		"/test(.*)":				"{PORT5000}/test$1",
		"/test1/(.*)":				"{PORT5000}/test1/$1",
		"/test2/(.*)":				"{PORT5000}/redirect2/$1",
		"/test3/(.*)":				"{PORT5000}/$1",
		"/nominatim/(.*)":			"http://nominatim.openstreetmap.org/$1",
		"/geonames/(.*)":			"http://api.geonames.org/geonames/$1",
		"/wws/(.*)":				"ws://127.0.0.1:5100/wws/$1"
	}
}
`

// We still need to figure out a way to kill the server gracefully.
// Right now, since we don't know how, we have to simply start the server
// on the first test, and keep it running for the duration of all tests.
const useSingleSandbox = true

type sandbox struct {
	front       *Server
	back        *backend
	frontWaiter chan error
	backWaiter  chan error
}

var singleSandbox *sandbox = nil

func (s *sandbox) start(t *testing.T) {
	if t != nil {
		//t.Log("Starting sandbox")
	}
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 0
	s.back = newBackend()
	s.back.httpServer.Addr = ":5000"
	s.backWaiter = goLaunchWaiter(s.back.listenAndServe)
	config := &Config{}
	err := config.LoadString(mainConfig)
	if err != nil {
		t.Error(err)
	}
	if s.front, err = NewServer(config); err != nil {
		t.Fatal(err)
	}

	launch := func() error {
		return s.front.ListenAndServe(":5002", "")
	}

	s.frontWaiter = goLaunchWaiter(launch)
	if t != nil {
		t.Log("Sandbox started")
	}
}

func (s *sandbox) stop(t *testing.T) {
	if useSingleSandbox && s == singleSandbox {
		// do nothing
	} else {
		//t.Log("Stopping sandbox")
		s.back.stop()
		s.front.Stop()
		t.Logf("backWaiter.stop: %v", <-s.backWaiter)
		t.Logf("frontWaiter.stop: %v", <-s.frontWaiter)
		//time.Sleep(time.Millisecond * 1000)
		//t.Log("Sandbox stopped")
	}
}

func startSandbox(t *testing.T) *sandbox {
	if useSingleSandbox {
		if singleSandbox == nil {
			singleSandbox = &sandbox{}
			singleSandbox.start(t)
		}
		return singleSandbox
	} else {
		s := &sandbox{}
		s.start(t)
		return s
	}
}

func doHttp(t *testing.T, method, url, body, expect_body string) {
	doHttpFunc(t, method, url, body, func(t *testing.T, resp_body string) {
		if resp_body != expect_body {
			t.Errorf("Expected \"%s\" received \"%s\"", expect_body, resp_body)
		}
	})
}

func doHttpFunc(t *testing.T, method, url, body string, verifyBodyFunc func(*testing.T, string)) {
	client := &http.Client{}
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body_response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	verifyBodyFunc(t, string(body_response))
}

func TestVariousURL(t *testing.T) {
	sb := startSandbox(t)

	doHttp(t, "GET", "http://127.0.0.1:5002/gert/jan/piet", "", "Route not found\n")                                                       // Invalid route
	doHttp(t, "GET", "http://127.0.0.1:5002/test1", "", "Method GET URL /test1 BODY ")                                                     // hello world
	doHttp(t, "GET", "http://127.0.0.1:5002/test2/path1/path2", "", "Method GET URL /redirect2/path1/path2 BODY ")                         // replace base url
	doHttp(t, "GET", "http://127.0.0.1:5002/test3/and/some/other/path/elements", "", "Method GET URL /and/some/other/path/elements BODY ") // remove base url
	doHttp(t, "GET", "http://127.0.0.1:5002/test1/testbody", "SomeBodyText", "Method GET URL /test1/testbody BODY SomeBodyText")           // body
	doHttp(t, "GET", "http://127.0.0.1:5002/test1/and/a/further/very/long/url/this/can/go/up/to/11kilobits/", "", "Method GET URL /test1/and/a/further/very/long/url/this/can/go/up/to/11kilobits/ BODY ")

	// other host
	doHttpFunc(t, "GET", "http://127.0.0.1:5002/nominatim/search/TechnoPark,+Stellenbosch?format=json", "", func(t *testing.T, resp_body string) {
		if strings.Index(resp_body, "Cape Winelands") == -1 {
			t.Errorf("nominatim search failed. Response body: %v", resp_body)
		}
	})

	sb.stop(t)
}

func TestMethods(t *testing.T) {
	sb := startSandbox(t)
	methods := [4]string{"GET", "DELETE", "POST", "PUT"}
	expected := [4]string{
		"Method GET URL /test1/testbody BODY SomeBodyText",
		"Method DELETE URL /test1/testbody BODY SomeBodyText",
		"Method POST URL /test1/testbody BODY SomeBodyText",
		"Method PUT URL /test1/testbody BODY SomeBodyText"}
	for index, method := range methods {
		doHttp(t, method, "http://127.0.0.1:5002/test1/testbody", "SomeBodyText", expected[index])
	}
	sb.stop(t)
}

/*
Im leaving this out as it is more a test of the testbox and the tcp protocol than router,
leaves lots of sockets in time_wait state, allowing following test to fail if run
a couple of times. This must definitely be run on the server with the tests running on another client box.
func TestManyClientSingleRequest(t *testing.T) {
	//Startup()
	var clientGroup sync.WaitGroup
	many := func(t *testing.T) {
		defer clientGroup.Done()
		const expected = "/redirect2/path1/path2"
		client := &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		}
		resp, err := client.Get("http://127.0.0.1:5002/test2/path1/path2")
		if err != nil {
			t.Error(err)
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Error(err)
		}
		resp.Body.Close()
		if !bytes.Equal(body, []byte(expected)) {
			t.Errorf("Expected %s received %s", expected, body)
		}
	}
	for i := 0; i < 1000; i++ {
		clientGroup.Add(1)
		go many(t)
	}
	clientGroup.Wait()
	//Shutdown()
}
*/
/*
// Leaving this out for same as above reason
func TestSingleClientManyRequests(t *testing.T) {
	//Startup()
	// Many request - single client
	var clientGroup sync.WaitGroup
	client := &http.Client{}
	many := func(t *testing.T) {
		defer clientGroup.Done()
		const expected = "/redirect2/path1/path2"
		resp, err := client.Get("http://127.0.0.1:5002/test2/path1/path2")
		if err != nil {
			t.Error(err)
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Error(err)
		}
		resp.Body.Close()
		if !bytes.Equal(body, []byte(expected)) {
			t.Errorf("Expected %s received %s", expected, body)
		}
	}
	for i := 0; i < 1000; i++ {
		clientGroup.Add(1)
		go many(t)
	}
	clientGroup.Wait()
	//Shutdown()
}
*/
func TestWebsocket(t *testing.T) {
	sb := startSandbox(t)
	expected := "Backend Websocket Received : testing webserver"
	go wsserver(t)
	time.Sleep(0.5 * 1e9) // Time for server to start
	origin := "http://localhost/"
	url := "ws://127.0.0.1:5002/wws/x"
	ws, err := websocket.Dial(url, "", origin)
	if err != nil {
		t.Fatalf("Initial dial failed: %v", err)
	}
	msg := "testing webserver"
	if e := websocket.Message.Send(ws, msg); e != nil {
		t.Fatal(e)
	}

	if e := websocket.Message.Receive(ws, &msg); e != nil {
		t.Fatal(e)
	}
	if msg != expected {
		t.Errorf("Expected %s received %s", expected, msg)
	}

	msg = "testing webserver"
	if e := websocket.Message.Send(ws, msg); e != nil {
		t.Fatal(e)
	}

	if e := websocket.Message.Receive(ws, &msg); e != nil {
		t.Fatal(e)
	}

	if msg != expected {
		t.Errorf("Expected \"%s\" received \"%s\"", expected, msg)
	}
	ws.Close()
	sb.stop(t)
}

func TestFinish(t *testing.T) {
	if useSingleSandbox {
		// trick singleSandbox into dying, by making it think it is not the one-and-only
		single := singleSandbox
		singleSandbox = nil
		single.stop(t)
	}
}

// Very simple backend server to use for testing the url is returned in the body for checking against
// the client expected return.
type backend struct {
	httpServer *http.Server
	listener   net.Listener
	waiter     sync.WaitGroup
}

func newBackend() *backend {
	b := &backend{}
	b.httpServer = &http.Server{}
	b.httpServer.Handler = b
	return b
}

func (b *backend) listenAndServe() error {
	addr := b.httpServer.Addr
	var err error
	if b.listener, err = net.Listen("tcp", addr); err != nil {
		return err
	}
	return b.httpServer.Serve(b.listener)
}

func (b *backend) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b.waiter.Add(1)
	defer b.waiter.Done()
	body, _ := ioutil.ReadAll(req.Body)
	req.Body.Close()

	fmt.Fprintf(w, "Method %s URL %s BODY %s", req.Method, html.EscapeString(req.URL.Path), body)
}

func (b *backend) stop() {
	if b.listener != nil {
		b.listener.Close()
	}
	b.waiter.Wait()
}

// Take as input a long running function that returns an error
// Return a channel that will wait on a new goroutine for that long running function to return
// When that function returns, its value is sent to the channel
func goLaunchWaiter(exec func() error) chan error {
	rchan := make(chan error)
	go func() {
		rchan <- exec()
	}()
	return rchan
}

func echoHandler(ws *websocket.Conn) {
	log.Println("In Echo")
	for {
		var msg string
		if err := websocket.Message.Receive(ws, &msg); err != nil {
			log.Printf("EchoServer Receive : %v\n", err)
			break
		}
		msg = "Backend Websocket Received : " + msg
		if err := websocket.Message.Send(ws, msg); err != nil {
			log.Printf("EchoServer Send : %v\n", err)
			break
		}
	}
	log.Println("Out of echo")
}

// simple websocket backend
func wsserver(t *testing.T) {
	http.Handle("/wws/", websocket.Handler(echoHandler))
	err := http.ListenAndServe(":5100", nil)
	if err != nil {
		t.Errorf("ListenAndServer : %s", err.Error())
	}
	log.Println("Out of server")
}
