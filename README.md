Router
======
This is designed to serve as a front-end to your web services, supporting both HTTP
and Websockets. You configure the router with a config file. This config file
specifies a set of simple URL rewrite rules. Requests are forwarded onto the
appropriate backend server, and the response is sent back to the client.

Why?
----
We needed a performant and well-behaved front door to all of our services which
could forward HTTP as well as Websockets. Nginx fits this bill, but since we
need to run on Windows, Nginx is a non-starter. We tried for some time to get
Apache to do this job, but we failed to get Apache to robustly forward websockets.
