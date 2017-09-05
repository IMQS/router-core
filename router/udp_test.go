package router

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
)

var udpConnPool *UDPConnectionPool
var wg sync.WaitGroup

/*
 * These tests do not actually launch a live router; they simply test the UDP connection pool.
 * Since UDP requests are connectionless there is no need for a server component
 */
func send(t *testing.T, port, iMsg int) {
	defer wg.Done()
	msg := []byte(strconv.Itoa(iMsg))
	address := fmt.Sprintf(":%v", port)
	if err := udpConnPool.Send(address, msg); err != nil {
		t.Fatal(err)
	}
}

func sendToPort(t *testing.T, port, nrMsgs int) {
	defer wg.Done()
	for i := 0; i < nrMsgs; i++ {
		wg.Add(1)
		go send(t, port, i)
	}
}

func TestEphemeralPortExhaustion(t *testing.T) {
	udpConnPool = NewUDPConnectionPool()

	wg.Add(1)
	go sendToPort(t, 8000, 200000)

	for i := 8000; i < 8100; i++ {
		wg.Add(1)
		go sendToPort(t, i, 2000)
	}

	wg.Wait()

	// connection pool is full, so this should error
	if err := udpConnPool.Send(":8101", []byte("message")); err == nil {
		t.Fatalf("Expected error: UDP connection pool limit reached")
	}
}
