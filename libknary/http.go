package libknary

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func PrepareRequest() (net.Listener, net.Listener) {
	// start listening on ports
	ln80, err := net.Listen("tcp", os.Getenv("BIND_ADDR")+":80")

	if err != nil {
		GiveHead(2)
		log.Fatal(err)
	}

	// open certificates
	cer, err := tls.LoadX509KeyPair(os.Getenv("TLS_CRT"), os.Getenv("TLS_KEY"))

	if err != nil {
		GiveHead(2)
		log.Fatal(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln443, err := tls.Listen("tcp", os.Getenv("BIND_ADDR")+":443", config)

	if err != nil {
		GiveHead(2)
		log.Fatal(err)
	}

	return ln80, ln443 // return listeners
}

func AcceptRequest(ln net.Listener, wg *sync.WaitGroup) {
	for {
		conn, err := ln.Accept() // accept connections forever

		if err != nil {
			Printy(err.Error(), 2)
		}

		go handleRequest(conn)
	}
	wg.Done()
}

func handleRequest(conn net.Conn) {
	// set timeout for reading responses
	if os.Getenv("TIMEOUT") != "" {
		i, err := strconv.Atoi(os.Getenv("TIMEOUT"))

		if err != nil {
			Printy(err.Error(), 2)
		}
		conn.SetDeadline(time.Now().Add(time.Second * time.Duration(i)))

	} else {
		conn.SetDeadline(time.Now().Add(time.Second * time.Duration(2))) // default 2 seconds
	}

	// read & store <=1kb of request
	buf := make([]byte, 1024)
	recBytes, err := conn.Read(buf)

	if err != nil {
		Printy(err.Error(), 2)
	}

	response := string(buf[:recBytes])
	headers := strings.Split(response, "\n")

	if os.Getenv("DEBUG") == "true" {
		Printy(conn.RemoteAddr().String(), 3)
		Printy(response, 3)
	}

	// search for our host header
	for _, header := range headers {
		if stringContains(header, os.Getenv("CANARY_DOMAIN")) {
			// a match made in heaven
			host := ""
			query := ""
			userAgent := ""

			for _, header := range headers {
				if stringContains(header, "Host") {
					host = header
				}
				if stringContains(header, "OPTIONS") ||
					stringContains(header, "GET") ||
					stringContains(header, "POST") ||
					stringContains(header, "PUT") ||
					stringContains(header, "PATCH") ||
					stringContains(header, "DELETE") {
					query = header
				}
				if stringContains(header, "User-Agent") {
					userAgent = header
				}
			}

			if !inBlacklist(host) {
				go sendMsg(host +
					"\n```" +
					"Query: " + query + "\n" +
					userAgent + "\n" +
					"From: " + conn.RemoteAddr().String() +
					"```")

				logger("[" + conn.RemoteAddr().String() + "]\n" + response)
			}
		}
	}

	conn.Write([]byte(" ")) // necessary as a 0 byte response triggers some clients to resend the request
	conn.Close()            // v. important lol
}
