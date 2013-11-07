Building:

* Run `env.bat`
* Run `go run src\github.com\IMQS\frontdoor\socklisten.go`. This will listen on localhost:8081
* Run `go run src\github.com\IMQS\frontdoor\frontdoor.go`. This will listen on localhost:8080
* You can now point Chrome at `localhost:8080` and in the console you should see messages
about communicating with a websocket. The 'socklisten' application will also spit out messages to stdout.

The project structure is screwed up right now -- ie 'frontdoor' inside 'frontdoor'.

To run SublimeText, you'll want to run it from the command line,
after running 'env.bat', so that your GOPATH is correct for GoSublime's sake.

We choose to bake the websocket library into this project to make 
CI easier. The websocket repo lives on a mercurial repo.

To update the websocket library, do this

* Run env.bat
* `go get code.google.com/p/go.net/websocket`
