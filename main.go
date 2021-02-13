package main

import (
	"github.com/fatih/color"
	"github.com/joho/godotenv"
	"github.com/miekg/dns"

	"fmt"
	"log"
	"os"
	"sync"

	"github.com/sudosammy/knary/libknary"
)

const (
	VERSION       = "2.3.3"
	GITHUB        = "https://github.com/sudosammy/knary"
	GITHUBVERSION = "https://raw.githubusercontent.com/sudosammy/knary/master/VERSION"
)

func main() {
	// load enviro variables
	err := godotenv.Load()

	if err != nil {
		libknary.GiveHead(2)
		log.Fatal(err)
	}

	// start maintenance timers
	libknary.StartMaintenance(VERSION, GITHUBVERSION, GITHUB)

	// get IP for knary.mycanary.com to use for DNS answers
	var EXT_IP string
	if os.Getenv("EXT_IP") == "" {
		res, err := libknary.PerformALookup("knary." + os.Getenv("CANARY_DOMAIN"))

		if err != nil {
			libknary.Printy("Are you sure your DNS is configured correctly?", 2)
			libknary.GiveHead(2)
			log.Fatal(err)
		}

		if res == "" {
			libknary.GiveHead(2)
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

	// load blacklist file & submit usage
	libknary.LoadBlacklist()
	go libknary.UsageStats(VERSION)

	if os.Getenv("HTTP") == "true" {
		libknary.Printy("Listening for http(s)://*."+os.Getenv("CANARY_DOMAIN")+" requests", 1)

		if os.Getenv("TLS_CRT") == "" || os.Getenv("TLS_KEY") == "" {
			libknary.GiveHead(2)
			log.Fatal("To use the HTTP canary you must specify the location of your domain's TLS certificates with TLS_CRT & TLS_KEY")
		}
	}
	if os.Getenv("DNS") == "true" {
		libknary.Printy("Listening for *.dns."+os.Getenv("CANARY_DOMAIN")+" DNS requests", 1)
	}
	if os.Getenv("BURP") == "true" {
		libknary.Printy("Working in collaborator compatibility mode on domain *."+os.Getenv("BURP_DOMAIN"), 1)

		if os.Getenv("BURP_DOMAIN") == "" || os.Getenv("BURP_DNS_PORT") == "" || os.Getenv("BURP_HTTP_PORT") == "" || os.Getenv("BURP_HTTPS_PORT") == "" {
			libknary.Printy("Required Burp Collaborator settings are missing. This might cause errors.", 2)
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

	if os.Getenv("HTTP") == "true" {
		ln80, ln443 := libknary.PrepareRequest()
		wg.Add(1)
		go libknary.AcceptRequest(ln443, &wg)
		wg.Add(1)
		go libknary.AcceptRequest(ln80, &wg)
	}

	wg.Wait()
}
