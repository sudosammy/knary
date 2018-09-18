package main

import (
	"github.com/fatih/color"
	"github.com/joho/godotenv"
	"github.com/miekg/dns"

	"fmt"
	"log"
	"os"
	"sync"
	"time"

	//"./libknary"
	"github.com/sudosammy/knary/libknary"
)

const (
	VERSION       = "1.1.1"
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

	// set ticker for update checks
	// https://stackoverflow.com/questions/16466320/is-there-a-way-to-do-repetitive-tasks-at-intervals-in-golang
	ticker := time.NewTicker(24 * time.Hour)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				libknary.CheckUpdate(VERSION, GITHUBVERSION, GITHUB)
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
	defer close(quit)

	// check for updates on first run
	libknary.CheckUpdate(VERSION, GITHUBVERSION, GITHUB)

	// verify that a slack or other webhook exists, surely there must be a better way
	var webhook int
	if os.Getenv("SLACK_WEBHOOK") == "" {
		webhook++
	}
	if os.Getenv("PUSHOVER_TOKEN") == "" {
		webhook++
	}
	if os.Getenv("DISCORD_WEBHOOK") == "" {
		webhook++
	}
	if webhook != 0 {
		libknary.GiveHead(2)
		log.Fatal("Webhooks could not be found in the .env file, check your .env file.")
	}

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

	if os.Getenv("HTTP") == "true" {
		libknary.Printy("Listening for http(s)://*."+os.Getenv("CANARY_DOMAIN")+" requests", 1)
	}
	if os.Getenv("DNS") == "true" {
		libknary.Printy("Listening for *.dns."+os.Getenv("CANARY_DOMAIN")+" DNS requests", 1)
	}
	if os.Getenv("SLACK_WEBHOOK") != "" {
		libknary.Printy("Posting to slack webhook: "+os.Getenv("SLACK_WEBHOOK"), 1)
	}
	if os.Getenv("PUSHOVER_TOKEN") != "" {
		libknary.Printy("Posting to pushover token: "+os.Getenv("PUSHOVER_TOKEN"), 1)
	}
	if os.Getenv("DISCORD_WEBHOOK") != "" {
		libknary.Printy("Posting to discord webhook: "+os.Getenv("DISCORD_WEBHOOK"), 1)
	}

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
