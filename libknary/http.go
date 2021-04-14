package libknary

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	//"net/http"
	//"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)
/*
	PrepareRequest80/443 changed dramatically in 3.3.0 when we scraped Burp Collab support:
	a) Burp collab is a shitty java app which frequently crashes and we gave up trying to support it,
	b) knary's new nameserver design would have required changes to the code in these functions,
	c) It wasn't a widely used feature for now. knary will probably support it again in the future.
*/
func PrepareRequest80() (net.Listener) {
	p80 := os.Getenv("BIND_ADDR") + ":80"	
	ln80, err := net.Listen("tcp", p80)
	if err != nil {
		GiveHead(2)
		log.Fatal(err)
	}

	return ln80
}

func PrepareRequest443() (net.Listener) {
	p443 := os.Getenv("BIND_ADDR") + ":443"
	cer, err := tls.LoadX509KeyPair(os.Getenv("TLS_CRT"), os.Getenv("TLS_KEY"))
	if err != nil {
		GiveHead(2)
		log.Fatal(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln443, err := tls.Listen("tcp", p443, config)
	if err != nil {
		GiveHead(2)
		log.Fatal(err)
	}

	return ln443
}

func AcceptRequest(ln net.Listener, wg *sync.WaitGroup) {
	for {
		conn, err := ln.Accept() // accept connections forever
		if err != nil {
			Printy(err.Error(), 2)
		}
		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) bool {
	// set timeout for reading responses
	_ = conn.SetDeadline(time.Now().Add(time.Second * time.Duration(2))) // 2 seconds

	// read & store <=4kb of request
	buf := make([]byte, 4096)
	recBytes, err := conn.Read(buf)

	if err != nil {
		Printy(err.Error(), 2)
		return false
	}

	response := string(buf[:recBytes])
	headers := strings.Split(response, "\n")
	lPort := conn.LocalAddr().(*net.TCPAddr).Port

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
			fwd := ""

			for _, header := range headers {
				if stringContains(header, "Host") {
					host = header
					host = strings.TrimRight(header, "\r\n") + ":"
					//using a reverse proxy, set ports back to the actual received ones
					if os.Getenv("BURP") == "true" {
						if lPort == 8880 {
							host = host + "80"
						} else if lPort == 8843 {
							host = host + "443"
						}
					} else {
						host = host + strconv.Itoa(lPort)
					}
				}
				// https://github.com/sudosammy/knary/issues/17
				if stringContains(header, "OPTIONS ") ||
					stringContains(header, "GET ") ||
					stringContains(header, "HEAD ") ||
					stringContains(header, "POST ") ||
					stringContains(header, "PUT ") ||
					stringContains(header, "PATCH ") ||
					stringContains(header, "DELETE ") ||
					stringContains(header, "CONNECT ") {
					query = header
				}
				if stringContains(header, "User-Agent") {
					userAgent = header
				}
				if stringContains(header, "X-Forwarded-For") {
					//this is pretty funny, and also very irritating.
					//Golang reverse proxy automagically adds the source IP address, but not the port.
					//We add the value we want in the prepareRequest function,
					//and strip off any values that don't have ports in this function.
					//It's then reconstructed and appended to the message
					val := strings.Split(header, ": ")[1]
					srcAndPort := []string{}
					mult := strings.Split(val, ",")
					if len(mult) > 1 {
						for _, srcaddr := range mult {
							if strings.Contains(srcaddr, ":") {
								srcAndPort = append(srcAndPort, srcaddr)
							}
						}
					} else {
						srcAndPort = mult
					}
					fwd = strings.Join(srcAndPort, "")
				}
			}

			if !inBlacklist(host, conn.RemoteAddr().String(), fwd) {
				msg := fmt.Sprintf("%s\n```Query: %s\n%s\nFrom: %s", host, query, userAgent, conn.RemoteAddr().String())
				if fwd != "" {
					msg += "\nX-Forwarded-For: " + fwd
				}
				go sendMsg(msg + "```")

				if fwd != "" {
					logger("INFO", fwd+" - "+host)
				} else {
					logger("INFO", conn.RemoteAddr().String()+" - "+host)
				}
			}
		}
	}

	conn.Write([]byte(" ")) // necessary as a 0 byte response triggers some clients to resend the request
	conn.Close()            // v. important lol
	return true
}
