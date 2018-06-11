package main

import (
	"github.com/fatih/color"
	"github.com/joho/godotenv"
	"github.com/miekg/dns"
	"github.com/robfig/cron"

	"fmt"
	"log" // lame
	"os"
	"sync"

	//"./libknary"
	"github.com/sudosammy/libknary"
)

const (
	VERSION       = "1.0.1"
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

	// set cron for update checks
	cron := cron.New()
	cron.AddFunc("@daily", func() { libknary.CheckUpdate(VERSION, GITHUBVERSION, GITHUB) })
	defer cron.Stop()
	// check for updates on first run
	libknary.CheckUpdate(VERSION, GITHUBVERSION, GITHUB)

	// get IP for knary.canary.com to use for DNS answers
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

	//should probably check that the external IP variable isn't blank here

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
		libknary.Printy("Listening for http(s)://*."+os.Getenv("CANARY_DOMAIN")+" requests", 1)
	}
	if os.Getenv("DNS") == "true" {
		libknary.Printy("Listening for *.dns."+os.Getenv("CANARY_DOMAIN")+" DNS requests", 1)
	}
	libknary.Printy("Posting to webhook: "+os.Getenv("SLACK_WEBHOOK"), 1)

	// setup waitgroups for DNS/HTTP go routines
	var wg sync.WaitGroup //there isn't actually any clean exit option, so we can just wait forever without having to worry about making the groups actually work (atm they don't)

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
