package libknary

import (
	"bufio"
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
		logger(updFail)
		go sendMsg(":warning: " + updFail)
		return false
	}

	response, err := http.Get(githubVersion)

	if err != nil {
		updFail := "Could not check for updates: " + err.Error()
		Printy(updFail, 2)
		logger(updFail)
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
			logger(updFail)
			return false
		}

		if running.Compare(current) != 0 {
			updMsg := "Your version of knary is *" + version + "* & the latest is *" + current.String() + "* - upgrade your binary here: " + githubURL
			Printy(updMsg, 2)
			logger(updMsg)
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
		if os.Getenv("DEBUG") == "true" {
			Printy("Blacklist file does not exist - ignoring", 3)
		}
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
	logger("Monitoring " + strconv.Itoa(count) + " items in blacklist")
	return true
}

func CheckLastHit() { // this runs once a day
	if len(blacklistMap) != 0 {
		// iterate through blacklist and look for items >30 days old
		for i := range blacklistMap { // foreach blacklist item
			expiryDate := blacklistMap[i].lastHit.AddDate(0, 0, 30)

			if time.Now().After(expiryDate) { // let 'em know it's old
				go sendMsg(":wrench: Blacklist item `" + blacklistMap[i].domain + "` hasn't had a hit in >30 days. Consider removing it. Configure `BLACKLIST_ALERTING` to supress.")
				logger("Blacklist item: " + blacklistMap[i].domain + " hasn't had a hit in >30 days. Consider removing it.")
				Printy("Blacklist item: "+blacklistMap[i].domain+" hasn't had a hit in >30 days. Consider removing it.", 1)
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
