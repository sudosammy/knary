package libknary

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func PrepareRequest80() net.Listener {
	p80 := os.Getenv("BIND_ADDR") + ":80"

	if os.Getenv("BURP_HTTP_PORT") != "" {
		p80 = "127.0.0.1:8880"  // set local port that knary will listen on as the client of the reverse proxy

		// to support our container friends - let the player choose the IP Burp is bound to
		burpIP := ""
		if os.Getenv("BURP_INT_IP") != "" {
			burpIP = os.Getenv("BURP_INT_IP")
		} else {
			burpIP = "127.0.0.1"
		}
		// start reverse proxy to direct requests appropriately
		go func() {
			e := http.ListenAndServe(os.Getenv("BIND_ADDR")+":80", &httputil.ReverseProxy{
				Director: func(r *http.Request) {
					r.URL.Scheme = "http"
					// if the incoming request has the burp suffix send it to collab
					if strings.HasSuffix(r.Host, os.Getenv("BURP_DOMAIN")) {
						r.URL.Host = burpIP + ":" + os.Getenv("BURP_HTTP_PORT")
					} else {
						// otherwise send it raw to the local knary port
						r.URL.Host = p80
						r.Header.Set("X-Forwarded-For", r.RemoteAddr) //add port version of x-fwded for
					}
				},
			})
			if e != nil {
				Printy(e.Error(), 2)
			}
		}()
	}

	ln80, err := net.Listen("tcp", p80)
	if err != nil {
		GiveHead(2)
		log.Fatal(err)
	}

	return ln80
}

func PrepareRequest443() net.Listener {
	p443 := os.Getenv("BIND_ADDR") + ":443"

	if os.Getenv("BURP_HTTPS_PORT") != "" {
		p443 = "127.0.0.1:8843"  // set local port that knary will listen on as the client of the reverse proxy

		// to support our container friends - let the player choose the IP Burp is bound to
		burpIP := ""
		if os.Getenv("BURP_INT_IP") != "" {
			burpIP = os.Getenv("BURP_INT_IP")
		} else {
			burpIP = "127.0.0.1"
		}
		go func() {
			e := http.ListenAndServeTLS(os.Getenv("BIND_ADDR")+":443", os.Getenv("TLS_CRT"), os.Getenv("TLS_KEY"),
				&httputil.ReverseProxy{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //it's localhost, we don't need to verify
					},
					Director: func(r *http.Request) {
						r.URL.Scheme = "https"
						//if the incoming request has the burp suffix send it to collab
						if strings.HasSuffix(r.Host, os.Getenv("BURP_DOMAIN")) {
							r.URL.Host = burpIP + ":" + os.Getenv("BURP_HTTPS_PORT")
						} else {
							//otherwise send it raw to the local knary port
							r.URL.Host = p443
							r.Header.Set("X-Forwarded-For", r.RemoteAddr)
						}
					},
				})
			if e != nil {
				Printy(e.Error(), 2)
			}
		}()
	}

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
			cookie := ""

			for _, header := range headers {
				if stringContains(header, "Host") {
					host = header
					host = strings.TrimRight(header, "\r\n") + ":"
					// using a reverse proxy, set ports back to the actual received ones
					if  os.Getenv("BURP_HTTP_PORT") != "" || os.Getenv("BURP_HTTPS_PORT") != "" {
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
				if stringContains(header, "Cookie") {
					cookie = header
				}
			}

			if inBlacklist(host, conn.RemoteAddr().String()) {
				return false
			}

			msg := fmt.Sprintf("%s\n```Query: %s\n%s\n%s\nFrom: %s", host, query, userAgent, cookie, conn.RemoteAddr().String())
			go sendMsg(msg + "```")
			logger("INFO", conn.RemoteAddr().String()+" - "+host)
		}
	}

	conn.Write([]byte(" ")) // necessary as a 0 byte response triggers some clients to resend the request
	conn.Close()            // v. important lol
	return true
}
