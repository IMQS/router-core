package router

import (
	"fmt"
	"net"
	"sync"
)

const udpConnectionLimit = 100

type udpConnection struct {
	net.Conn
	sync.Mutex
}

// UDPConnectionPool is a connection pool for sending UDP requests
type UDPConnectionPool struct {
	pool map[string]*udpConnection
	sync.Mutex
}

// NewUDPConnectionPool is a util method to construct a new UDPConnectionPool
func NewUDPConnectionPool() *UDPConnectionPool {
	return &UDPConnectionPool{pool: make(map[string]*udpConnection)}
}

func (p *UDPConnectionPool) getConnection(address string) (*udpConnection, error) {
	p.Lock()
	defer p.Unlock()
	udpConn, ok := p.pool[address]
	if !ok {
		if len(p.pool) >= udpConnectionLimit {
			return nil, fmt.Errorf("UDP connection pool limit reached")
		}

		fmt.Println("Adding UDP connection to UDP connection pool : ", address)
		conn, err := net.Dial("udp", address)
		if err != nil {
			return nil, err
		}

		udpConn = &udpConnection{conn, sync.Mutex{}}
		p.pool[address] = udpConn
	}
	return udpConn, nil
}

// Send sends a UDP request with msg as content to the specified address
func (p *UDPConnectionPool) Send(address string, msg []byte) error {
	udpConn, err := p.getConnection(address)
	if err != nil {
		return err
	}

	udpConn.Lock() // need to lock before writing to a UDP connection otherwise an additional ephemeral port get's consumed
	_, err = udpConn.Write(msg)
	udpConn.Unlock()
	return err
}
