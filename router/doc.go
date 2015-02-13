/*
Package router forwards HTTP and Websocket requests to backend
services.

Its input is a configuration file which specifies
a simple set of URL rewrite rules. The rule that matches
determines the backend server that will receive the request.

TLS Renegotiation

Microsoft has published a forked version of net/http which supports TLS renegotiation.
It doesn't look like the Go team plans on adding this to the core.
See https://github.com/golang/go/issues/5742
We need this in order to communicate with https://hub.puretechltd.com/Token, which I assume
is running on some version of IIS. I haven't asked Pure whether it is running on Azure, but
that is certainly possible.

In order to keep the code simple, we always use the Microsoft net/http fork as
our HTTP roundtripper. We'll have to keep an eye on this, to make sure that we stay up
to date with any changes in the Go standard library.

Authentication Middle Man

The router supports acting as an authenticating proxy, where the authentication information
is stored on the server. This is used in scenarios where a client does not want to
create separate identities for everybody who can use IMQS. Instead, the client gives us
a blanket login that covers all the functionality, and then we enable that functionality
for specific IMQS users, via Authaus permission bits.

The router automatically logs in to the backend authentication service, and stores the
session tokens in RAM. Future requests to that same backend automatically get the
session token added into the HTTP headers before forwarding the request.

*/
package router
