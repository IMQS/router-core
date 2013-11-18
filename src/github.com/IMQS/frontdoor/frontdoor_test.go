package frontdoor

import (
	"bytes"
	"code.google.com/p/go.net/websocket"
	"fmt"
	"github.com/IMQS/frontdoor/frontdoor"
	"html"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

var srv *frontdoor.Server
var back *backend

func Startup() {
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 0
	back = NewBackend()
	back.HttpServer.Addr = ":5000"
	go back.ListenAndServe()
	srv = frontdoor.NewServer(`C:\imqsroot\frontdoor\src\github.com\IMQS\frontdoor\test_config.json`)
	srv.HttpServer.Addr = ":80"
	go srv.ListenAndServe()
	time.Sleep(1 * 1e9)
}

func Shutdown() {
	back.Stop()
	srv.Stop()
	time.Sleep(1 * 1e9)
}

func init() {
	// Startup frontdoor and beckend for all tests
	Startup()
}

func TestSimple(t *testing.T) {
	const expected = "/test1"
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1" + expected)
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

func TestLongURL(t *testing.T) {
	const expected = "/test1/and/a/further/very/long/url/this/can/go/up/to/11kilobits/"
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1" + expected)
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

func TestNotProxied(t *testing.T) {
	const expected = ""
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1/gert/jan/piet")
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

func TestReplaceBaseUrl(t *testing.T) {
	const expected = "/redirect2/path1/path2"
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1/test2/path1/path2")
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

func TestRemoveBaseUrl(t *testing.T) {
	const expected = "/and/some/aother/path/elements"
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1/test3/and/some/aother/path/elements")
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

func TestHostReplace(t *testing.T) {
	client := &http.Client{}
	resp, err := client.Get("http://127.0.0.1/nominatim/search/TechnoPark,+Stellenbosch?format=json")
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
}

/*
Im leaving this out as it is more a test of the testbox and the tcp protocol than frontdoor,
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
		resp, err := client.Get("http://127.0.0.1/test2/path1/path2")
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
		resp, err := client.Get("http://127.0.0.1/test2/path1/path2")
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
	expected := "Backend Websocket Received : testing webserver"
	go wsserver(t)
	time.Sleep(0.5 * 1e9) // Time for server to start
	origin := "http://localhost/"
	url := "ws://127.0.0.1:80/wws"
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

}

func TestDone(t *testing.T) {
	Shutdown()
}

// Very simple backend server to use for testing
type backend struct {
	HttpServer *http.Server
	listener   net.Listener
	waiter     sync.WaitGroup
}

func NewBackend() *backend {
	b := &backend{}
	b.HttpServer = &http.Server{}
	b.HttpServer.Handler = b
	return b
}

func (b *backend) ListenAndServe() {
	addr := b.HttpServer.Addr
	var err error
	b.listener, err = net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	b.HttpServer.Serve(b.listener)
}

func (b *backend) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b.waiter.Add(1)
	defer b.waiter.Done()
	fmt.Fprintf(w, "%s", html.EscapeString(req.URL.Path))
}

func (b *backend) Stop() {
	b.listener.Close()
	b.waiter.Wait()
}

func echoHandler(ws *websocket.Conn) {
	var msg string
	if err := websocket.Message.Receive(ws, &msg); err != nil {

	}
	msg = "Backend Websocket Received : " + msg
	if err := websocket.Message.Send(ws, msg); err != nil {
	}
}

// simple websocket backend
func wsserver(t *testing.T) {
	http.Handle("/wws", websocket.Handler(echoHandler))
	err := http.ListenAndServe(":5100", nil)
	if err != nil {
		t.Fatalf("ListenAndServer : %s", err.Error())
	}
}

var externalExpected = `[{"place_id":"8072499","licence":"Data \u00a9 OpenStreetMap contributors, ODbL 1.0. http:\/\/www.openstreetmap.org\/copyright","osm_type":"node","osm_id":"824654551","boundingbox":["-33.9658088684082","-33.9658050537109","18.8361072540283","18.836109161377"],"lat":"-33.9658052","lon":"18.8361077","display_name":"Technopark, Stellenbosch Local Municipality, Cape Winelands District Municipality, Western Cape, South Africa","class":"place","type":"suburb","importance":0.45,"icon":"http:\/\/nominatim.openstreetmap.org\/images\/mapicons\/poi_place_village.p.20.png"},{"place_id":"16447281","licence":"Data \u00a9 OpenStreetMap contributors, ODbL 1.0. http:\/\/www.openstreetmap.org\/copyright","osm_type":"node","osm_id":"1465367920","boundingbox":["-33.9660797119141","-33.9660758972168","18.8340282440186","18.8340301513672"],"lat":"-33.9660774","lon":"18.8340294","display_name":"Protea Hotel Stellenbosch, meson, Technopark, Stellenbosch Local Municipality, Cape Winelands District Municipality, Western Cape, 7600, South Africa","class":"tourism","type":"hotel","importance":0.201,"icon":"http:\/\/nominatim.openstreetmap.org\/images\/mapicons\/accommodation_hotel2.p.20.png"}]`
