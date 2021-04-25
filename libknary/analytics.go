package libknary

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

/*
	This function collects very basic analytics to track knary usage.
	It does NOT collect anything that could be tied back to you easily; however, does take a SHA256 hash of your knary domain name.
	If you have any thoughts about knary you can contact me on Twitter: @sudosammy or GitHub: https://github.com/sudosammy/knary
*/
type features struct {
	DNS      bool `json:"dns"`
	HTTP     bool `json:"http"`
	BURP     bool `json:"burp"`
	SLACK    bool `json:"slack"`
	DISCORD  bool `json:"discord"`
	PUSHOVER bool `json:"pushover"`
	TEAMS    bool `json:"teams"`
}

type analy struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	Status    int    `json:"day"`
	Blacklist int    `json:"blacklist"`
	Offset    int    `json:"offset"`
	Timezone  string `json:"timezone"`
	features  `json:"features"`
}

var day = 0

func UsageStats(version string) bool {
	trackingDomain := "https://knary.sam.ooo" // make this an empty string to sinkhole analytics

	if os.Getenv("CANARY_DOMAIN") == "" || trackingDomain == "" {
		return false
	}

	// a unique & desensitised ID
	knaryID := sha256.New()
	_, _ = knaryID.Write([]byte(os.Getenv("CANARY_DOMAIN")))
	anonKnaryID := hex.EncodeToString(knaryID.Sum(nil))

	zone, offset := time.Now().Zone() // timezone

	day++ // track how long knary has been running for

	// disgusting
	dns, https, burp, slack, discord, pushover, teams := false, false, false, false, false, false, false
	if os.Getenv("DNS") == "true" {
		dns = true
	}
	if os.Getenv("HTTP") == "true" {
		https = true
	}
	if os.Getenv("BURP_DOMAIN") == "true" {
		burp = true
	}
	if os.Getenv("SLACK_WEBHOOK") != "" {
		slack = true
	}
	if os.Getenv("DISCORD_WEBHOOK") != "" {
		discord = true
	}
	if os.Getenv("PUSHOVER_USER") != "" {
		pushover = true
	}
	if os.Getenv("TEAMS_WEBHOOK") != "" {
		teams = true
	}

	jsonValues, err := json.Marshal(&analy{
		anonKnaryID,
		version,
		day,
		len(blacklistMap),
		(offset / 60 / 60),
		zone,
		features{
			dns,
			https,
			burp,
			slack,
			discord,
			pushover,
			teams,
		},
	})

	if err != nil {
		if os.Getenv("DEBUG") == "true" {
			Printy(err.Error(), 3)
		}
		return false
	}

	c := &http.Client{
		Timeout: 10 * time.Second,
	}
	_, err = c.Post(trackingDomain, "application/json", bytes.NewBuffer(jsonValues))

	if err != nil {
		if os.Getenv("DEBUG") == "true" {
			Printy(err.Error(), 3)
		}
		return false
	}

	return true
}
