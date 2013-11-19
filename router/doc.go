/*
Package router forwards HTTP and Websocket requests to backend
services.

Its input is a configuration file which specifies
a simple set of URL rewrite rules. The rule that matches
determines the backend server that will receive the request.
*/
package router
