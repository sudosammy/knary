package main

import (
	"github.com/joho/godotenv"
	"github.com/fatih/color"
	"github.com/robfig/cron"
	"github.com/blang/semver"
	"github.com/miekg/dns"
	"fmt"
	"net"
	"os"
	"log"
	"time"
	"strings"
	"crypto/tls"
	"net/http" // lame
	"bytes"
	"strconv"
	"bufio"
	"sync"
)

const (
	VERSION = "1.0.1"
	GITHUB = "https://github.com/sudosammy/knary"
	GITHUB_VERSION = "https://raw.githubusercontent.com/sudosammy/knary/master/VERSION"
)

func main() {
	// load enviro variables
	err := godotenv.Load()

	if err != nil {
		giveHead(2)
		log.Fatal(err)
	}

	// set cron for update checks
	cron := cron.New()
	cron.AddFunc("@daily", func() { checkUpdate() })
	defer cron.Stop()
	// check for updates on first run
	checkUpdate()

	// get IP for knary.canary.com to use for DNS answers
	var EXT_IP string
	if os.Getenv("EXT_IP") == "" {
		res, err := performALookup("knary." + os.Getenv("CANARY_DOMAIN"))

		if err != nil {
			printy("Are you sure your DNS is configured correctly?", 2)
			giveHead(2)
			log.Fatal(err)
		}

		if res == "" {
			giveHead(2)
			log.Fatal("Couldn't find IP address for knary." + os.Getenv("CANARY_DOMAIN") + ". Consider setting EXT_IP")
		}

		EXT_IP = res
	}

	// yo yo yo we doing a thing bb
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	red.Println(` __                           
|  |--.-----.---.-.----.--.--.
|    <|     |  _  |   _|  |  |
|__|__|__|__|___._|__| |___  |`)
	green.Printf(` @sudosammy     v` + VERSION + ` `)
	red.Println(`|_____|`)
	fmt.Println()

	if os.Getenv("HTTP") == "true" {
		printy("Listening for http(s)://*." + os.Getenv("CANARY_DOMAIN") + " requests", 1)
	}
	if os.Getenv("DNS") == "true" {
		printy("Listening for *.dns." + os.Getenv("CANARY_DOMAIN") + " DNS requests", 1)
	}
	printy("Posting to webhook: " + os.Getenv("SLACK_WEBHOOK"), 1)

	// setup waitgroups for DNS/HTTP go routines
	var wg sync.WaitGroup

	if os.Getenv("DNS") == "true" {
		wg.Add(1)
		// https://bl.ocks.org/tianon/063c8083c215be29b83a
		// There must be a better way to pass "EXT_IP" along without an anonymous function AND copied variable
		dns.HandleFunc(os.Getenv("CANARY_DOMAIN") + ".", func(w dns.ResponseWriter, r *dns.Msg) { handleDNS(w, r, EXT_IP) })
		go acceptDNS(&wg)
	}

	if os.Getenv("HTTP") == "true" {
		wg.Add(2)
		ln80, ln443 := prepareRequest()
		go acceptRequest(ln443, &wg)
		go acceptRequest(ln80, &wg)
	}

	wg.Wait()
}

func acceptDNS(wg *sync.WaitGroup) {
	// start DNS server
	server := &dns.Server{Addr: os.Getenv("BIND_ADDR") + ":53", Net: "udp"}
	err := server.ListenAndServe()

	if err != nil {
		giveHead(2)
		log.Fatal(err)
	}

	defer server.Shutdown()
	wg.Done()
}

// DNS is specified in RFC 1034 / RFC 1035
// +---------------------+
// |        Header       |
// +---------------------+
// |       Question      | the question for the name server
// +---------------------+
// |        Answer       | RRs answering the question
// +---------------------+
// |      Authority      | RRs pointing toward an authority
// +---------------------+
// |      Additional     | RRs holding additional information
// +---------------------+
//
//  DNS Header
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      ID                       |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    QDCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ANCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    NSCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ARCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

func handleDNS(w dns.ResponseWriter, r *dns.Msg, EXT_IP string) {
	// many thanks to the original author of this function
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Authoritative = true
	parseDNS(m, w.RemoteAddr().String(), EXT_IP)
	w.WriteMsg(m)
}

func parseDNS(m *dns.Msg, ipaddr string, EXT_IP string) {
	// for each DNS question to our nameserver
	// there can be multiple questions in the question section of a single request
	for _, q := range m.Question {
		// we only care about A questions
		if q.Qtype == dns.TypeA {
			if os.Getenv("DEBUG") == "true" {
				printy("DNS question for: " + q.Name, 3)
			}

			if !inBlacklist(q.Name) {
				// spit the IP address to remove the port
				// be wary of IPv6
				ipSlice := strings.Split(ipaddr, ":")
				ipSlice = ipSlice[:len(ipSlice)-1]
				ipaddrNoPort := strings.Join(ipSlice[:], ",")

				reverse, _ := dns.ReverseAddr(ipaddrNoPort)

				if reverse == "" {
					go sendMsg("DNS: " + q.Name +
					"```" +
					"From: " + ipaddr +
					"```")
					logger("[" + ipaddr + "]\n" + q.Name)

				} else {
					go sendMsg("DNS: " + q.Name +
					"```" +
					"From: " + ipaddr + "\n" +
					"PTR: " + reverse +
					"```")
					logger("[" + ipaddr + "]\n" + "[" + reverse + "]\n" + q.Name)
				}	
			}

			// if EXT_IP is set, it overrules the A lookup 
			if os.Getenv("EXT_IP") == "" {
				if os.Getenv("DEBUG") == "true" {
					printy("Responding with: " + EXT_IP, 3)
				}

				rr, _ := dns.NewRR(fmt.Sprintf("%s IN 60 A %s", q.Name, EXT_IP))
				m.Answer = append(m.Answer, rr)

			} else {
				if os.Getenv("DEBUG") == "true" {
					printy("Responding with: " + os.Getenv("EXT_IP"), 3)
				}
				
				rr, _ := dns.NewRR(fmt.Sprintf("%s IN 60 A %s", q.Name, os.Getenv("EXT_IP")))
				m.Answer = append(m.Answer, rr)
			}
		}
	}
}

func performALookup(domain string) (string, error) {
	// perform an A lookup on the canary domain and use that for our reply
	kMsg := new(dns.Msg)
	kMsg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// query dns server for dns.mycanary.com.
	var nameServ string
	if os.Getenv("DNS_SERVER") == "" {
		nameServ = "8.8.8.8"
	} else {
		nameServ = os.Getenv("DNS_SERVER")
	}

	answ, _, err := new(dns.Client).Exchange(kMsg, nameServ + ":53")

	if err != nil {
		return "", err;
	}

	// https://stackoverflow.com/questions/38625233/what-does-key-ok-k-dns-a-mean-in-go
	if t, ok := answ.Answer[0].(*dns.A); ok {
		if os.Getenv("DEBUG") == "true" {
			printy("Answering DNS requests with: " + t.A.String(), 3)
		}
		return t.A.String(), nil
	}

	return "", nil
}

func prepareRequest() (net.Listener, net.Listener) {
	// start listening on ports
	ln80, err := net.Listen("tcp", os.Getenv("BIND_ADDR") + ":80")

	if err != nil {
		giveHead(2)
		log.Fatal(err)
	}

	// open certificates
	cer, err := tls.LoadX509KeyPair(os.Getenv("TLS_CRT"), os.Getenv("TLS_KEY"))

	if err != nil {
		giveHead(2)
		log.Fatal(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln443, err := tls.Listen("tcp", os.Getenv("BIND_ADDR") + ":443", config)

	if err != nil {
		giveHead(2)
		log.Fatal(err)
	}

	return ln80, ln443 // return listeners
}

func acceptRequest(ln net.Listener, wg *sync.WaitGroup) {
	for {
		conn, err := ln.Accept() // accept connections forever

		if err != nil {
			printy(err.Error(), 2)
		}

		go handleRequest(conn)
	}
	wg.Done()
}

func handleRequest(conn net.Conn) {
	// set timeout for reading responses
	if (os.Getenv("TIMEOUT") != "") {
		i, err := strconv.Atoi(os.Getenv("TIMEOUT"))

		if err != nil {
			printy(err.Error(), 2)
		}

		conn.SetDeadline(time.Now().Add(time.Second * time.Duration(i)))

	} else {
		conn.SetDeadline(time.Now().Add(time.Second * time.Duration(2))) // default 2 seconds
	}
	
	// read & store <=1kb of request
	buf := make([]byte, 1024)
	recBytes, err := conn.Read(buf)

	if err != nil {
		printy(err.Error(), 2)
	}

	response := string(buf[:recBytes])
	headers := strings.Split(response, "\n")

	localPort := conn.LocalAddr().(*net.TCPAddr).Port

	if os.Getenv("DEBUG") == "true" {
		printy("raddr " + conn.RemoteAddr().String(), 3)
		printy("laddr " + conn.LocalAddr().String(), 3)

		printy(response, 3)
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
					host = strings.TrimRight(header, "\r\n") + ":" + strconv.Itoa(localPort)
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
	conn.Close() // v. important lol
}

func sendMsg(msg string) {
	jsonMsg := []byte(`{"username":"knary","icon_emoji":":bird:","text":"` + msg + `"}`)
	_, err := http.Post(os.Getenv("SLACK_WEBHOOK"), "application/json", bytes.NewBuffer(jsonMsg))

	if err != nil {
		printy(err.Error(), 2)
	}
}

func inBlacklist(host string) bool {
	if _, err := os.Stat(os.Getenv("BLACKLIST_FILE")); os.IsNotExist(err) {
		if os.Getenv("DEBUG") == "true" {
			printy("Blacklist file does not exist - ignoring", 3)
		}
		return false
	}

	blklist, err := os.Open(os.Getenv("BLACKLIST_FILE"))
	defer blklist.Close()

	if err != nil {
		printy(err.Error() + " - ignoring", 3)
		return false
	}

	scanner := bufio.NewScanner(blklist)

	for scanner.Scan() { // foreach blacklist item
		if strings.Contains(host, scanner.Text()) && !strings.Contains(host, "." + scanner.Text()) {
			// matches blacklist.domain but not x.blacklist.domain
			if os.Getenv("DEBUG") == "true" {
				printy(scanner.Text() + " found in blacklist", 3)
			}
			return true
		}
	}
	return false
}

func logger(message string) {
	if os.Getenv("LOG_FILE") != "" {
		f, err := os.OpenFile(os.Getenv("LOG_FILE"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		
		if err != nil {
			printy(err.Error(), 2)
		}

		defer f.Close()

		// add newline if not present
		lastChar := message[len(message)-1:]
		var toLog string

		if lastChar != "\n" {
			toLog = message + "\n"
		} else {
			toLog = message
		}

		// log with timestamp
		if _, err = f.WriteString("[" + time.Now().Format(time.RFC850) + "]\n" + toLog); err != nil {
			printy(err.Error(), 2)
		}
	}
}

func printy(msg string, col int) {
	giveHead(col)
	fmt.Println(msg)
}

func stringContains(stringA string, stringB string) bool {
	return strings.Contains(
		strings.ToLower(stringA),
		strings.ToLower(stringB),
	)
}

func giveHead(colour int) {
	// make pretty [+] things
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	blue := color.New(color.FgBlue)
	white := color.New(color.FgWhite)

	switch colour {
	case 1: // success
		fmt.Printf("[")
		green.Printf("+")
		fmt.Printf("] ")
	case 2: // error
		fmt.Printf("[")
		red.Printf("+")
		fmt.Printf("] ")
	case 3: // debug
		fmt.Printf("[")
		blue.Printf("+")
		fmt.Printf("] ")
	default:
		fmt.Printf("[")
		white.Printf("+")
		fmt.Printf("] ")
	}
}

func checkUpdate() bool {
	running, err := semver.Make(VERSION)

	if err != nil {
		updFail := "Could not check for updates: " + err.Error()
		printy(updFail, 2)
		logger(updFail)
		return false
	}

	response, err := http.Get(GITHUB_VERSION)

	if err != nil {
		updFail := "Could not check for updates: " + err.Error()
		printy(updFail, 2)
		logger(updFail)
		return false
	}

	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body) // refusing to import ioutil

	for scanner.Scan() { // foreach line
		current, err := semver.Make(scanner.Text())

		if err != nil {
			updFail := "Could not check for updates. GitHub response !semver format"
			printy(updFail, 2)
			logger(updFail)
			return false
		}

		if running.Compare(current) != 0 {
			updMsg := ":warning: Your version of knary is *" + VERSION + "* & the latest is *" + current.String() + "* - upgrade your binary here: " + GITHUB
			printy(updMsg, 2)
			logger(updMsg)
			go sendMsg(updMsg)
			return true
		}
	}
	
	return false
}
