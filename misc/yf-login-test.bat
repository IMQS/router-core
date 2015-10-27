@echo off
rem This is a very poor excuse for a unit test, but by inspecting router-error.log
rem while running this, we can at least stress some of the cache contention paths of
rem the yellowfin transparent auth system.

rem You must replace USERNAME:PASSWORD before running
rem Also, you must set GOMAXPROCS=2 (or more) before launching the router

rem ab -A USERNAME:PASSWORD -n 1000 -c 4 -s 5 -k http://localhost/yellowfin/#

rem Inspect router-error.log, and you should expect to see a few cases of:
rem "Backing off on yellowfin login: ...."
rem Following by a single
rem "Transparent login to yellowfin: ..."

rem The point of this test is to stress that locking system
rem I don't make it a unit test, because that would require mocking the auth service,
rem and I just don't have the energy to set that up now.