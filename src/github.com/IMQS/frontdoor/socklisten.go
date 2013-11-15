package main

import (
	"code.google.com/p/go.net/websocket"
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", handleHttp)
	http.Handle("/wws", websocket.Handler(handler))
	http.ListenAndServe("localhost:8081", nil)
}

func handleHttp(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Serving HTML")
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(code))
}

func handler(c *websocket.Conn) {
	fmt.Printf("Opening\n")
	//buf := [256]byte{}
	for {
		/*
			nRead, err := c.Read(buf[:])
			if err != nil {
				fmt.Printf("Closing socket: %v\n", err)
				break
			}
			inStr := string(buf[0:nRead])
			fmt.Printf("Received: %v\n", inStr)
			fmt.Fprintf(c, "You said: %v", inStr)
		*/
		inMsg := ""
		if e := websocket.Message.Receive(c, &inMsg); e != nil {
			fmt.Printf("Closing (%v)\n", e)
			break
		}
		fmt.Printf("Received: %v\n", inMsg)
		outMsg := fmt.Sprintf("You said: %v", inMsg)
		websocket.Message.Send(c, outMsg)
		websocket.Message.Send(c, "A random other thing")
		websocket.Message.Send(c, "A random yet another thing")
	}
	c.Close()
}

const code = `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
</head>

<body>
</body>

<script>
var ws = new WebSocket("ws://localhost/wws");
var isOpen = false;
var nMsg = 0;

repeat = function() {
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
		setTimeout(repeat, 2000);
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
</script>
</html>
`
