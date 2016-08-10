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

Authentication Pass-Through

The router supports acting as an authenticating proxy, where the authentication information
is stored on the server. This is used in scenarios where a client does not want to
create separate identities for everybody who can use IMQS. Instead, the client gives us
a blanket login that covers all the functionality, and then we enable that functionality
for specific IMQS users, via Authaus permission bits.

The router automatically logs in to the backend authentication service, and stores the
session tokens in RAM. Future requests to that same backend automatically get the
session token added into the HTTP headers before forwarding the request.

Stopping A Server

The Go standard library does not make it possible to stop an HTTP server. At least, it is
not possible to do so without creating your own Listener. BUT, if you create your own
Listener, then you don't get HTTP/2 functionality. This is why we have no Stop() function.

Known issues:

The pass-through authentication does not handle the situation where the backend has cleared it's
store of session tokens. For example, if one was to login to Yellowfin, and then Yellowfin gets
restarted, and consequently forgets it's session tokens, the router would not realize that our
own cached tokens are now invalid. To solve this, one would need to implement a check inside
ServeHTTP(), which would monitor expected error responses such as 401, and then force the
pass-through authentication system to discard it's cached information. I tried implementing this,
assuming that Yellowfin would return a 401 upon receiving an unauthorized request. However, it does
not do this. Instead, it sends back a login page. In order to detect this, one would need to
perform deep inspection on the response body, which is something I'd rather not do unless it
is absolutely necessary. So, we rely instead on expiring session tokens ourselves, and hope
that Yellowfin is not restarted without the router also being restarted.

*/
package router
