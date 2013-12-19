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
	"bytes"
	"code.google.com/p/go.net/websocket"
	"flag"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const mainConfig = `
{
	"http://127.0.0.1:5000":{
	 "proxy":false,
	 "matches":{
		 "/test1":{"route":"(.*)|$1"},
		 "/test2":{"route":"/test2(.*)|/redirect2$1"},
		 "/test3":{"route":"/test3(.*)|$1"},
		 "/":{"route":"(.$)|$1"}
     }},
	"http://nominatim.openstreetmap.org/":{
	 "proxy":true,
	 "matches":{
		 "/nominatim":{"route":"/nominatim(.*)|$1"}
     }},
    "http://api.geonames.org":{
	"proxy":false,
	"matches":{
	    "/geonames":{"route":"/geonames(.*)|$1"}
	}},
	"ws://127.0.0.1:5100":{
	 "proxy":false,
	 "matches":{
		 "/wws":{"route":"(.*)|$1"}
	 }}
}
`
const clientConfig = `
{
	"http://nominatim.openstreetmap.org/":{
	 "proxy":false
     },
    "http://api.geonames.org":{
	"proxy":true
    },
	"ws://127.0.0.1:5100":{
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
	var err error
	var routeConfig *RouterConfig
	if routeConfig, err = ParseRoutes(strings.NewReader(mainConfig), strings.NewReader(clientConfig)); err != nil {
		if t != nil {
			t.Error(err)
		}
	}
	flags := flag.NewFlagSet("router", flag.ExitOnError)
	flags.String("accesslog", "router_access.log", "access log file")
	flags.String("errorlog", "router_error.log", "error log file")
	flags.String("proxy", "", "proxy server:port")
	flags.Bool("disablekeepalive", false, "Disable Keep Alives")
	flags.Uint("maxidleconnections", 50, "Maximum Idle Connections")
	flags.Uint("responseheadertimeout", 60, "Header Timeout")
	flags.Parse(os.Args[2:])
	if s.front, err = NewServer(routeConfig, flags); err != nil {
		if t != nil {
			t.Error(err)
		}
	}
	s.front.HttpServer.Addr = ":5002"
	s.frontWaiter = goLaunchWaiter(s.front.ListenAndServe)
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

func TestSimple(t *testing.T) {
	sb := startSandbox(t)
	const expected = "Method GET URL /test1 BODY "
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:5002/test1")
	if err != nil {
		t.Error(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	resp.Body.Close()
	if !bytes.Equal(body, []byte(expected)) {
		t.Errorf("Expected %s received \"%s\"", expected, body)
	}
	sb.stop(t)
}

func TestLongURL(t *testing.T) {
	sb := startSandbox(t)
	const expected = "Method GET URL /test1/and/a/further/very/long/url/this/can/go/up/to/11kilobits/ BODY "
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:5002/test1/and/a/further/very/long/url/this/can/go/up/to/11kilobits/")
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
	sb.stop(t)
}

func TestNotProxied(t *testing.T) {
	sb := startSandbox(t)
	const expected = "Not Found\n"
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:5002/gert/jan/piet")
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
	sb.stop(t)
}

func TestReplaceBaseUrl(t *testing.T) {
	sb := startSandbox(t)
	const expected = "Method GET URL /redirect2/path1/path2 BODY "
	client := &http.Client{}
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
	sb.stop(t)
}

func TestRemoveBaseUrl(t *testing.T) {
	sb := startSandbox(t)
	const expected = "Method GET URL /and/some/other/path/elements BODY "
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:5002/test3/and/some/other/path/elements")
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
	sb.stop(t)
}

var externalExpected = `[{"place_id":"8072499","licence":"Data \u00a9 OpenStreetMap contributors, ODbL 1.0. http:\/\/www.openstreetmap.org\/copyright","osm_type":"node","osm_id":"824654551","boundingbox":["-33.9658088684082","-33.9658050537109","18.8361072540283","18.836109161377"],"lat":"-33.9658052","lon":"18.8361077","display_name":"Technopark, Stellenbosch Local Municipality, Cape Winelands District Municipality, Western Cape, South Africa","class":"place","type":"suburb","importance":0.45,"icon":"http:\/\/nominatim.openstreetmap.org\/images\/mapicons\/poi_place_village.p.20.png"},{"place_id":"16447281","licence":"Data \u00a9 OpenStreetMap contributors, ODbL 1.0. http:\/\/www.openstreetmap.org\/copyright","osm_type":"node","osm_id":"1465367920","boundingbox":["-33.9660797119141","-33.9660758972168","18.8340282440186","18.8340301513672"],"lat":"-33.9660774","lon":"18.8340294","display_name":"Protea Hotel Stellenbosch, meson, Technopark, Stellenbosch Local Municipality, Cape Winelands District Municipality, Western Cape, 7600, South Africa","class":"tourism","type":"hotel","importance":0.201,"icon":"http:\/\/nominatim.openstreetmap.org\/images\/mapicons\/accommodation_hotel2.p.20.png"}]`

func TestHostReplace(t *testing.T) {
	sb := startSandbox(t)
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1:5002/nominatim/search/TechnoPark,+Stellenbosch?format=json")
	if err != nil {
		t.Error(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	resp.Body.Close()
	strbody := string(body)
	if strbody != externalExpected {
		t.Errorf("Expected:\n%s \nreceived :\n%s", externalExpected, body)
	}
	sb.stop(t)
}

func TestBody(t *testing.T) {
	sb := startSandbox(t)
	const expected = "Method GET URL /test1/testbody BODY SomeBodyText"
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://127.0.0.1:5002/test1/testbody", strings.NewReader("SomeBodyText"))
	if err != nil {
		t.Error(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	resp.Body.Close()
	strbody := string(body)
	if strbody != expected {
		t.Errorf("Expected \"%s\" received \"%s\"", expected, body)
	}
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
	client := &http.Client{}
	for index, method := range methods {
		req, err := http.NewRequest(method, "http://127.0.0.1:5002/test1/testbody", strings.NewReader("SomeBodyText"))
		if err != nil {
			t.Error(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Error(err)
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Error(err)
		}
		resp.Body.Close()
		strbody := string(body)
		if strbody != expected[index] {
			t.Errorf("Expected \"%s\" received \"%s\"", expected[index], body)
		}
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
	url := "ws://127.0.0.1:5002/wws"
	ws, err := websocket.Dial(url, "", origin)
	if err != nil {
		t.Fatal(err)
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
	http.Handle("/wws", websocket.Handler(echoHandler))
	err := http.ListenAndServe(":5100", nil)
	if err != nil {
		t.Errorf("ListenAndServer : %s", err.Error())
	}
	log.Println("Out of server")
}
