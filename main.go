package main

import (
	"github.com/fatih/color"
	"github.com/joho/godotenv"
	"github.com/miekg/dns"

	"flag"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/sudosammy/knary/v3/libknary"
)

const (
	VERSION       = "3.4.7"
	GITHUB        = "https://github.com/sudosammy/knary"
	GITHUBVERSION = "https://raw.githubusercontent.com/sudosammy/knary/master/VERSION"
)

func main() {
	var helpS = flag.Bool("h", false, "Show help")
	var help = flag.Bool("help", false, "")
	var versionS = flag.Bool("v", false, "Show version")
	var version = flag.Bool("version", false, "")
	flag.Parse() // https://github.com/golang/go/issues/35761
	if *help || *helpS {
		libknary.Printy("Version: "+VERSION, 1)
		libknary.Printy("Find all configuration options and example .env files here: "+GITHUB+"/tree/master/examples", 3)
		os.Exit(0)
	}
	if *version || *versionS {
		libknary.Printy("Version: "+VERSION, 1)
		os.Exit(0)
	}

	// load enviro variables
	err := godotenv.Load()
	if os.Getenv("CANARY_DOMAIN") == "" {
		libknary.Printy("Required environment variables not found. Check location of .env file and/or running user's environment", 2)
		libknary.GiveHead(2)
		log.Fatal(err)
	}

	err = libknary.LoadDomains(os.Getenv("CANARY_DOMAIN"))
	if err != nil {
		libknary.GiveHead(2)
		log.Fatal(err)
	}

	// start maintenance timers
	libknary.StartMaintenance(VERSION, GITHUBVERSION, GITHUB)

	// get the glue record of knary to use in our responses
	var EXT_IP string
	if os.Getenv("EXT_IP") == "" {
		// try to guess the glue record
		res, err := libknary.GuessIP(libknary.GetFirstDomain())

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
		// test that user inputted a valid IP addr.
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

	// load lists, zone file & submit usage
	libknary.LoadAllowlist()
	libknary.LoadBlacklist()
	libknary.LoadZone()
	go libknary.UsageStats(VERSION)

	if os.Getenv("HTTP") == "true" && os.Getenv("LETS_ENCRYPT") == "" && (os.Getenv("TLS_CRT") == "" || os.Getenv("TLS_KEY") == "") {
		for _, cdomain := range libknary.GetDomains() {
			libknary.Printy("Listening for http://*."+cdomain+" requests", 1)
		}
		libknary.Printy("Without LETS_ENCRYPT or TLS_* environment variables set you will only be able to make HTTP (port 80) requests to knary", 2)
	} else if os.Getenv("HTTP") == "true" && (os.Getenv("LETS_ENCRYPT") != "" || os.Getenv("TLS_KEY") != "") {
		for _, cdomain := range libknary.GetDomains() {
			libknary.Printy("Listening for http(s)://*."+cdomain+" requests", 1)
		}
	}
	if os.Getenv("DNS") == "true" {
		if os.Getenv("DNS_SUBDOMAIN") != "" {
			for _, cdomain := range libknary.GetDomains() {
				libknary.Printy("Listening for *."+os.Getenv("DNS_SUBDOMAIN")+"."+cdomain+" DNS requests", 1)
			}
		} else {
			for _, cdomain := range libknary.GetDomains() {
				libknary.Printy("Listening for *."+cdomain+" DNS requests", 1)
			}
		}
	}
	if os.Getenv("BURP_DOMAIN") != "" {
		libknary.IsDeprecated("BURP_*", "REVERSE_PROXY_*", "3.5.0")
		libknary.Printy("(Deprecated) Working in collaborator compatibility mode on subdomain *."+os.Getenv("BURP_DOMAIN"), 1)

		if os.Getenv("BURP_DNS_PORT") == "" || os.Getenv("BURP_HTTP_PORT") == "" || os.Getenv("BURP_HTTPS_PORT") == "" {
			libknary.Printy("Not all Burp Collaborator settings are set. This might cause errors.", 2)
		}
	}
	if os.Getenv("REVERSE_PROXY_DOMAIN") != "" {
		libknary.Printy("Proxying enabled on requests to: *."+os.Getenv("REVERSE_PROXY_DOMAIN"), 1)

		if os.Getenv("REVERSE_PROXY_HTTP") == "" || os.Getenv("REVERSE_PROXY_HTTPS") == "" || os.Getenv("REVERSE_PROXY_DNS") == "" {
			libknary.Printy("Not all reverse proxy settings are set. This might cause errors.", 2)
		}
	}
	if os.Getenv("REVERSE_PROXY_DOMAIN") != "" && os.Getenv("BURP_DOMAIN") != "" {
		libknary.Printy("Configuring both BURP_* and REVERSE_PROXY_* is not supported and may break things!", 2)
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
	if os.Getenv("TELEGRAM_CHATID") != "" {
		libknary.Printy("Posting to Telegram Chat ID: "+os.Getenv("TELEGRAM_CHATID"), 1)
	}

	// setup waitgroups for DNS/HTTP go routines
	var wg sync.WaitGroup // there isn't actually any clean exit option, so we can just wait forever

	if os.Getenv("DNS") == "true" {
		wg.Add(1)
		// https://bl.ocks.org/tianon/063c8083c215be29b83a
		// There must be a better way to pass "EXT_IP" along without an anonymous function AND copied variable
		for _, cdomain := range libknary.GetDomains() {
			dns.HandleFunc(cdomain+".", func(w dns.ResponseWriter, r *dns.Msg) { libknary.HandleDNS(w, r, EXT_IP) })
		}
		go libknary.AcceptDNS(&wg)
	}

	// generate a let's encrypt certificate
	if os.Getenv("LETS_ENCRYPT") != "" && os.Getenv("HTTP") == "true" && os.Getenv("DNS") == "true" && (os.Getenv("TLS_CRT") == "" || os.Getenv("TLS_KEY") == "") {
		libknary.StartLetsEncrypt()
		libknary.Printy("Let's Encrypt certificate is loaded", 1)

	} else if os.Getenv("LETS_ENCRYPT") != "" && (os.Getenv("HTTP") != "true" || os.Getenv("DNS") != "true") {
		libknary.Printy("HTTP and DNS environment variables must be set to \"true\" to use Let's Encrypt. We'll continue without Let's Encrypt", 2)
		os.Setenv("LETS_ENCRYPT", "") // clear variable to not confuse certificate renewal logic

	} else if os.Getenv("TLS_CRT") != "" && os.Getenv("LETS_ENCRYPT") != "" {
		libknary.Printy("TLS_* and LETS_ENCRYPT environment variables found. We'll use the TLS_* set certificates", 2)
		os.Setenv("LETS_ENCRYPT", "") // clear variable to not confuse certificate renewal logic
	}

	if os.Getenv("HTTP") == "true" {
		// HTTP
		ln80 := libknary.Listen80()
		wg.Add(1)
		go libknary.Accept80(ln80)

		if os.Getenv("TLS_CRT") != "" && os.Getenv("TLS_KEY") != "" {
			// HTTPS
			restart := make(chan bool)
			ln443 := libknary.Listen443()
			wg.Add(1)
			go libknary.Accept443(ln443, &wg, restart)

			_, _ = libknary.CheckTLSExpiry(30) // check TLS expiry on first launch of knary
			go libknary.TLSmonitor(restart)    // monitor filesystem changes to the TLS cert to trigger a reboot
		}
	}

	// these go after all the screen printing for neatness
	libknary.CheckUpdate(VERSION, GITHUBVERSION, GITHUB)
	libknary.HeartBeat(VERSION, true)

	wg.Wait()
}
