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

type routerConfig struct {
	scheme              string // "http" or "https"
	reverseProxyHost    string // env var for reverse proxy host
	knaryListenerURL    string // local knary listener address
	useTLS              bool   // whether to use TLS for backend connections
	knaryListenerUseTLS bool   // whether knary listener uses TLS
}

// createReverseProxyHandler creates a handler that routes requests to reverse proxy or knary
func createReverseProxyHandler(cfg routerConfig) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// reverse proxy config
		if os.Getenv("REVERSE_PROXY_DOMAIN") != "" && strings.HasSuffix(r.Host, os.Getenv("REVERSE_PROXY_DOMAIN")) {
			proxy := &httputil.ReverseProxy{
				Director: func(req *http.Request) {
					req.URL.Scheme = cfg.scheme
					req.URL.Host = cfg.reverseProxyHost
				},
			}
			if cfg.useTLS {
				proxy.Transport = &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //it's localhost, we don't need to verify
				}
			}
			proxy.ServeHTTP(w, r)
			return
		}

		// For knary canary requests, proxy to knary listener
		r.Header.Set("X-Forwarded-For", r.RemoteAddr)
		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				if cfg.knaryListenerUseTLS {
					req.URL.Scheme = "https"
				} else {
					req.URL.Scheme = "http"
				}
				req.URL.Host = cfg.knaryListenerURL
			},
		}
		if cfg.knaryListenerUseTLS {
			proxy.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //it's localhost, we don't need to verify
			}
		}
		proxy.ServeHTTP(w, r)
	})
}

func Listen80() net.Listener {
	p80 := os.Getenv("BIND_ADDR") + ":80"

	if os.Getenv("REVERSE_PROXY_HTTP") != "" {
		p80 = "127.0.0.1:8880" // set local port that knary will listen on as the client of the reverse proxy

		// start custom handler to route requests appropriately
		go func() {
			handler := createReverseProxyHandler(routerConfig{
				scheme:              "http",
				reverseProxyHost:    os.Getenv("REVERSE_PROXY_HTTP"),
				knaryListenerURL:    "127.0.0.1:8880",
				useTLS:              false,
				knaryListenerUseTLS: false,
			})

			e := http.ListenAndServe(os.Getenv("BIND_ADDR")+":80", handler)
			if e != nil {
				Printy(e.Error(), 2)
			}
		}()
	}

	ln80, err := net.Listen("tcp", p80)
	if err != nil {
		logger("ERROR", err.Error())
		GiveHead(2)
		log.Fatal(err)
	}

	return ln80
}

func Accept80(ln net.Listener) {
	for {
		conn, err := ln.Accept() // accept connections forever
		if err != nil {
			Printy(err.Error(), 2)
		}
		go handleRequest(conn)
	}
}

func Listen443() net.Listener {
	p443 := os.Getenv("BIND_ADDR") + ":443"

	if os.Getenv("REVERSE_PROXY_HTTPS") != "" {
		p443 = "127.0.0.1:8843" // set local port that knary will listen on as the client of the reverse proxy

		go func() {
			handler := createReverseProxyHandler(routerConfig{
				scheme:              "https",
				reverseProxyHost:    os.Getenv("REVERSE_PROXY_HTTPS"),
				knaryListenerURL:    "127.0.0.1:8843",
				useTLS:              true,
				knaryListenerUseTLS: true,
			})

			e := http.ListenAndServeTLS(os.Getenv("BIND_ADDR")+":443", os.Getenv("TLS_CRT"), os.Getenv("TLS_KEY"), handler)
			if e != nil {
				Printy(e.Error(), 2)
			}
		}()
	}

	cer, err := tls.LoadX509KeyPair(os.Getenv("TLS_CRT"), os.Getenv("TLS_KEY"))
	if err != nil {
		logger("ERROR", err.Error())
		GiveHead(2)
		log.Fatal(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln443, err := tls.Listen("tcp", p443, config)
	if err != nil {
		logger("ERROR", err.Error())
		GiveHead(2)
		log.Fatal(err)
	}

	return ln443
}

func Accept443(ln net.Listener, wg *sync.WaitGroup, restart <-chan bool) {
	for {
		select {
		case <-restart:
			ln.Close()           // close listener so we can restart it
			ln443 := Listen443() // restart listener
			go Accept443(ln443, wg, restart)
			msg := "HTTPS / TLS server successfully reloaded."
			logger("INFO", msg)
			Printy(msg, 3)
			go sendMsg(":lock: " + msg)
			return // important

		default:
			conn, err := ln.Accept() // accept connections until channel says stop
			if err != nil {
				Printy(err.Error(), 2)
			}
			go handleRequest(conn)
		}
	}
}

func httpRespond(conn net.Conn) bool {
	conn.Write([]byte(" ")) // necessary as a 0 byte response triggers some clients to resend the request
	conn.Close()            // v. important lol
	return true
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
		if ok, _ := returnSuffix(header); ok {
			// a match made in heaven
			host := ""
			query := ""
			userAgent := ""
			cookie := ""
			fwd := ""

			for _, header := range headers {
				if stringContains(header, "Host") {
					host = strings.TrimRight(header, "\r\n") + ":"
					// using a reverse proxy, set ports back to the actual received ones
					if os.Getenv("REVERSE_PROXY_HTTP") != "" || os.Getenv("REVERSE_PROXY_HTTPS") != "" {
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
							if strings.Contains(srcaddr, ":") { // this probs breaks IPv6
								srcAndPort = append(srcAndPort, srcaddr)
							}
						}
					} else {
						srcAndPort = mult
					}
					fwd = strings.Join(srcAndPort, "")
				}
			}

			// take off the headers for the allow/denylist search
			searchUserAgent := strings.TrimPrefix(strings.ToLower(userAgent), "user-agent:")
			searchDomain := strings.TrimPrefix(strings.ToLower(host), "host:") // trim off the "Host:" section of header

			// these conditionals were bugged in <=3.4.6 whereby subdomains/ips in the allowlist weren't allowed unless the user-agent was ALSO in the allowlist
			// it should be easier to grok now
			if inBlacklist(searchUserAgent, searchDomain, conn.RemoteAddr().String(), fwd) { // inBlacklist returns false on empty/unused denylists
				if os.Getenv("DEBUG") == "true" {
					Printy("HTTP request blocked by denylist", 3)
				}
				return httpRespond(conn)
			}

			if !inAllowlist(searchUserAgent, searchDomain, conn.RemoteAddr().String(), fwd) { // inAllowlist returns true on empty/unused allowlists
				if os.Getenv("DEBUG") == "true" {
					Printy("HTTP request blocked by allowlist", 3)
				}
				return httpRespond(conn)
			}

			var msg string
			var fromIP string

			if fwd != "" {
				fromIP = fwd // use this when burp collab mode is active
			} else {
				fromIP = conn.RemoteAddr().String()
			}

			if cookie != "" {
				if os.Getenv("FULL_HTTP_REQUEST") != "" {
					msg = fmt.Sprintf("%s\n```Query: %s\n%s\n%s\nFrom: %s\n\n---------- FULL REQUEST ----------\n%s\n----------------------------------", host, query, userAgent, cookie, fromIP, response)
				} else {
					msg = fmt.Sprintf("%s\n```Query: %s\n%s\n%s\nFrom: %s", host, query, userAgent, cookie, fromIP)
				}
			} else {
				if os.Getenv("FULL_HTTP_REQUEST") != "" {
					msg = fmt.Sprintf("%s\n```Query: %s\n%s\nFrom: %s\n\n---------- FULL REQUEST ----------\n%s\n----------------------------------", host, query, userAgent, fromIP, response)
				} else {
					msg = fmt.Sprintf("%s\n```Query: %s\n%s\nFrom: %s", host, query, userAgent, fromIP)
				}
			}

			go sendMsg(msg + "```")
			if os.Getenv("DEBUG") == "true" {
				logger("INFO", fromIP+" - "+host)
			}
		}
	}

	return httpRespond(conn)
}
