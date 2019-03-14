package libknary

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blang/semver"
)

func stringContains(stringA string, stringB string) bool { // this runs once a day
	return strings.Contains(
		strings.ToLower(stringA),
		strings.ToLower(stringB),
	)
}

func CheckUpdate(version string, githubVersion string, githubURL string) bool {
	running, err := semver.Make(version)

	if err != nil {
		updFail := "Could not check for updates: " + err.Error()
		Printy(updFail, 2)
		logger("WARNING", updFail)
		go sendMsg(":warning: " + updFail)
		return false
	}

	response, err := http.Get(githubVersion)

	if err != nil {
		updFail := "Could not check for updates: " + err.Error()
		Printy(updFail, 2)
		logger("WARNING", updFail)
		go sendMsg(":warning: " + updFail)
		return false
	}

	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body) // refusing to import ioutil

	for scanner.Scan() { // foreach line
		current, err := semver.Make(scanner.Text())

		if err != nil {
			updFail := "Could not check for updates. GitHub response !semver format"
			Printy(updFail, 2)
			logger("WARNING", updFail)
			return false
		}

		if running.Compare(current) != 0 {
			updMsg := "Your version of knary is *" + version + "* & the latest is *" + current.String() + "* - upgrade your binary here: " + githubURL
			Printy(updMsg, 2)
			logger("WARNING", updMsg)
			go sendMsg(":warning: " + updMsg)
			return true
		}
	}

	return false
}

// map for blacklist
type blacklist struct {
	domain  string
	lastHit time.Time
}

var blacklistMap = map[int]blacklist{}

func LoadBlacklist() bool {
	// load blacklist file into struct on startup
	if _, err := os.Stat(os.Getenv("BLACKLIST_FILE")); os.IsNotExist(err) {
		return false
	}

	blklist, err := os.Open(os.Getenv("BLACKLIST_FILE"))
	defer blklist.Close()

	if err != nil {
		Printy(err.Error()+" - ignoring", 3)
		return false
	}

	scanner := bufio.NewScanner(blklist)
	count := 0
	for scanner.Scan() { // foreach blacklist item
		blacklistMap[count] = blacklist{scanner.Text(), time.Now()} // add to struct
		count++
	}

	Printy("Monitoring "+strconv.Itoa(count)+" items in blacklist", 1)
	logger("INFO", "Monitoring "+strconv.Itoa(count)+" items in blacklist")
	return true
}

func CheckLastHit() { // this runs once a day
	if len(blacklistMap) != 0 {
		// iterate through blacklist and look for items >14 days old
		for i := range blacklistMap { // foreach blacklist item
			expiryDate := blacklistMap[i].lastHit.AddDate(0, 0, 14)

			if time.Now().After(expiryDate) { // let 'em know it's old
				go sendMsg(":wrench: Blacklist item `" + blacklistMap[i].domain + "` hasn't had a hit in >14 days. Consider removing it. Configure `BLACKLIST_ALERTING` to supress.")
				logger("INFO", "Blacklist item: "+blacklistMap[i].domain+" hasn't had a hit in >14 days. Consider removing it.")
				Printy("Blacklist item: "+blacklistMap[i].domain+" hasn't had a hit in >14 days. Consider removing it.", 1)
			}
		}
	}
}

func inBlacklist(needles ...string) bool {
	for _, needle := range needles {
		for i := range blacklistMap { // foreach blacklist item
			if strings.Contains(needle, blacklistMap[i].domain) && !strings.Contains(needle, "."+blacklistMap[i].domain) {
				// matches blacklist.domain or 1.1.1.1 but not x.blacklist.domain
				updBL := blacklistMap[i]
				updBL.lastHit = time.Now() // update last hit
				blacklistMap[i] = updBL

				if os.Getenv("DEBUG") == "true" {
					Printy(blacklistMap[i].domain+" found in blacklist", 3)
				}
				return true
			}
		}
	}
	return false
}

/*
* This function collects very basic analytics to track knary usage.
* If you have any thoughts about knary you can contact me on Twitter: @sudosammy
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
	_,_ = knaryID.Write([]byte(os.Getenv("CANARY_DOMAIN")))
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
	if os.Getenv("BURP") == "true" {
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

	_, err = http.Post(trackingDomain, "application/json", bytes.NewBuffer(jsonValues))

	if err != nil {
		if os.Getenv("DEBUG") == "true" {
			Printy(err.Error(), 3)
		}
		return false
	}

	return true
}
