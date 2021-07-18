package main

import (
	"github.com/fatih/color"
	"github.com/joho/godotenv"
	"github.com/miekg/dns"

	"fmt"
	"log"
	"os"
	"sync"
	"strconv"

	"github.com/sudosammy/knary/libknary"
)

const (
	VERSION       = "3.3.0"
	GITHUB        = "https://github.com/sudosammy/knary"
	GITHUBVERSION = "https://raw.githubusercontent.com/sudosammy/knary/master/VERSION"
)

func main() {
	// load enviro variables
	err := godotenv.Load()
	if os.Getenv("CANARY_DOMAIN") == "" {
		libknary.Printy("Required environment variables not found. Check location of .env file and/or running user's environment", 2)
		libknary.GiveHead(2)
		log.Fatal(err)
	}

	// start maintenance timers
	libknary.StartMaintenance(VERSION, GITHUBVERSION, GITHUB)

	// get the glue record of knary to use in our responses
	var EXT_IP string
	if os.Getenv("EXT_IP") == "" {
		// try to guess the glue record
		res, err := libknary.GuessIP(os.Getenv("CANARY_DOMAIN"))

		if err != nil {
			libknary.Printy("Are you sure your DNS is configured correctly?", 2)
			libknary.GiveHead(2)
			log.Fatal(err)
		}

		if !libknary.IsIP(res) {
			libknary.Printy("Couldn't parse response from glue record. You should set EXT_IP", 2)
			return
		}

		if os.Getenv("DEBUG") == "true" {
			libknary.Printy("Found glue record! We will answer DNS requests with: "+res, 3)
		}

		EXT_IP = res
	} else {
		// test that user inputed a valid IP addr.
		if !libknary.IsIP(os.Getenv("EXT_IP")) {
			libknary.Printy("Couldn't parse EXT_IP. Are you sure it's a valid IP address?", 2)
			return
		}

		EXT_IP = os.Getenv("EXT_IP")
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

	// load blacklist file, zone file & submit usage
	libknary.LoadBlacklist()
	libknary.LoadZone()
	go libknary.UsageStats(VERSION)

	if os.Getenv("HTTP") == "true" && os.Getenv("LETS_ENCRYPT") == "" && (os.Getenv("TLS_CRT") == "" || os.Getenv("TLS_KEY") == "") {
		libknary.Printy("Listening for http://*."+os.Getenv("CANARY_DOMAIN")+" requests", 1)
		libknary.Printy("Without LETS_ENCRYPT or TLS_* environment variables set you will only be able to make HTTP (port 80) requests to knary", 2)
	} else if (os.Getenv("HTTP") == "true" && (os.Getenv("LETS_ENCRYPT") != "" || os.Getenv("TLS_KEY") != "")) {
		libknary.Printy("Listening for http(s)://*."+os.Getenv("CANARY_DOMAIN")+" requests", 1)
	}
	if os.Getenv("DNS") == "true" {
		libknary.Printy("Listening for *."+os.Getenv("CANARY_DOMAIN")+" DNS requests", 1)
	}
	if os.Getenv("BURP_DOMAIN") != "" {
		libknary.Printy("Working in collaborator compatibility mode on subdomain *."+os.Getenv("BURP_DOMAIN"), 1)

		if os.Getenv("BURP_DNS_PORT") == "" || os.Getenv("BURP_HTTP_PORT") == "" || os.Getenv("BURP_HTTPS_PORT") == "" {
			libknary.Printy("Not all Burp Collaborator settings are set. This might cause errors.", 2)
		}
	}
	if os.Getenv("SLACK_WEBHOOK") != "" {
		libknary.Printy("Posting to webhook: "+os.Getenv("SLACK_WEBHOOK"), 1)
	}
	if os.Getenv("DISCORD_WEBHOOK") != "" {
		libknary.Printy("Posting to webhook: "+os.Getenv("DISCORD_WEBHOOK"), 1)
	}
	if os.Getenv("PUSHOVER_USER") != "" {
		libknary.Printy("Posting to Pushover user: "+os.Getenv("PUSHOVER_USER"), 1)
	}
	if os.Getenv("TEAMS_WEBHOOK") != "" {
		libknary.Printy("Posting to webhook: "+os.Getenv("TEAMS_WEBHOOK"), 1)
	}
	if os.Getenv("LARK_WEBHOOK") != "" {
		libknary.Printy("Posting to webhook: "+os.Getenv("LARK_WEBHOOK"), 1)
	}

	// these go after all the screen prining for neatness
	libknary.CheckUpdate(VERSION, GITHUBVERSION, GITHUB)
	libknary.HeartBeat(VERSION, true)

	// setup waitgroups for DNS/HTTP go routines
	var wg sync.WaitGroup // there isn't actually any clean exit option, so we can just wait forever

	if os.Getenv("DNS") == "true" {
		wg.Add(1)
		// https://bl.ocks.org/tianon/063c8083c215be29b83a
		// There must be a better way to pass "EXT_IP" along without an anonymous function AND copied variable
		dns.HandleFunc(os.Getenv("CANARY_DOMAIN")+".", func(w dns.ResponseWriter, r *dns.Msg) { libknary.HandleDNS(w, r, EXT_IP) })
		go libknary.AcceptDNS(&wg)
	}

	// generate a let's encrypt certificate
	if os.Getenv("LETS_ENCRYPT") != "" && os.Getenv("HTTP") == "true" && os.Getenv("DNS") == "true" && (os.Getenv("TLS_CRT") == "" || os.Getenv("TLS_KEY") == "") {
		certName := libknary.StartLetsEncrypt()
		// out of this we need to set TLS_CRT and TLS_KEY
		// TODO make these not rely on hardcoded paths
		os.Setenv("TLS_CRT","certs/"+certName+".crt")
		os.Setenv("TLS_KEY","certs/"+certName+".key")
		libknary.Printy("Let's Encrypt certificate is loaded", 1)

	} else if (os.Getenv("LETS_ENCRYPT") != "" && (os.Getenv("HTTP") != "true" || os.Getenv("DNS") != "true")) {
		libknary.Printy("HTTP and DNS environment variables must be set to \"true\" to use Let's Encrypt. We'll continue without Let's Encrypt", 2)
		os.Setenv("LETS_ENCRYPT","") // clear variable to not confuse certificate renewal logic

	} else if os.Getenv("TLS_CRT") != "" || os.Getenv("TLS_KEY") != "" {
		libknary.Printy("TLS_* and LETS_ENCRYPT environment variables found. We'll use the TLS_* set certificates", 2)
		os.Setenv("LETS_ENCRYPT","") // clear variable to not confuse certificate renewal logic
	}

	if os.Getenv("HTTP") == "true" {
		ln80 := libknary.PrepareRequest80()
		// HTTP
		wg.Add(1)
		go libknary.AcceptRequest(ln80, &wg)

		if os.Getenv("TLS_CRT") != "" && os.Getenv("TLS_KEY") != "" {
			// HTTPS
			ln443 := libknary.PrepareRequest443()
			wg.Add(1)
			go libknary.AcceptRequest(ln443, &wg)
			// check TLS expiry on first lauch of knary
			_, expiry := libknary.CheckTLSExpiry(30)
			libknary.Printy("TLS certificate expires in " + strconv.Itoa(expiry) + " days", 3)
		}
	}

	wg.Wait()
}
