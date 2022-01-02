package libknary

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Functions that control whether a match will notify a webhook.
// Currently the allow and denylists.

// map for allowlist
type allowlist struct {
	allow string
}

var allowed = map[int]allowlist{}
var allowCount = 0

// map for denylist
type blacklist struct {
	mutex sync.Mutex
	deny  map[string]time.Time
}

var denied = blacklist{deny: make(map[string]time.Time)}
var denyCount = 0

// add or update a denied domain/IP
func (a *blacklist) updateD(term string) bool {
	if term == "" {
		return false // would happen if there's no X-Forwarded-For header
	}
	item := standerdiseListItem(term)
	a.mutex.Lock()
	a.deny[item] = time.Now()
	a.mutex.Unlock()
	return true
}

// search for a denied domain/IP
func (a *blacklist) searchD(term string) bool {
	item := standerdiseListItem(term)
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.deny[item]; ok {
		return true // found!
	}
	return false
}

func standerdiseListItem(term string) string {
	d := strings.ToLower(term) // lowercase
	d = strings.TrimSpace(d)   // remove any surrounding whitespaces
	var sTerm string

	if IsIP(d) {
		sTerm, _ = splitPort(d) // yeet port off IP
	} else {
		domain := strings.Split(d, ":")            // split on port number (if exists)
		sTerm = strings.TrimSuffix(domain[0], ".") // remove trailing FQDN dot if present
	}

	return sTerm
}

func LoadAllowlist() (bool, error) {
	// load allowlist file into struct on startup
	if _, err := os.Stat(os.Getenv("ALLOWLIST_FILE")); os.IsNotExist(err) {
		return false, err
	}

	alwlist, err := os.Open(os.Getenv("ALLOWLIST_FILE"))
	defer alwlist.Close()

	if err != nil {
		Printy(err.Error()+" - ignoring", 3)
		return false, err
	}

	scanner := bufio.NewScanner(alwlist)

	for scanner.Scan() { // foreach allowed item
		if scanner.Text() != "" {
			allowed[allowCount] = allowlist{standerdiseListItem(scanner.Text())}
			allowCount++
		}
	}

	Printy("Monitoring "+strconv.Itoa(allowCount)+" items in allowlist", 1)
	logger("INFO", "Monitoring "+strconv.Itoa(allowCount)+" items in allowlist")
	return true, nil
}

func LoadBlacklist() (bool, error) {
	if os.Getenv("BLACKLIST_FILE") != "" {
		// deprecation warning
		Printy("The environment variable \"DENYLIST_FILE\" has superseded \"BLACKLIST_FILE\". Please update your configuration.", 2)
	}
	// load denylist file into struct on startup
	if _, err := os.Stat(os.Getenv("DENYLIST_FILE")); os.IsNotExist(err) {
		return false, err
	}

	blklist, err := os.Open(os.Getenv("DENYLIST_FILE"))
	defer blklist.Close()

	if err != nil {
		Printy(err.Error()+" - ignoring", 3)
		return false, err
	}

	scanner := bufio.NewScanner(blklist)

	for scanner.Scan() { // foreach denied item
		if scanner.Text() != "" {
			denied.updateD(scanner.Text())
			denyCount++
		}
	}

	Printy("Monitoring "+strconv.Itoa(denyCount)+" items in denylist", 1)
	logger("INFO", "Monitoring "+strconv.Itoa(denyCount)+" items in denylist")
	return true, nil
}

func inAllowlist(needles ...string) bool {
	if allowed[0].allow == "" {
		return true // if there is no allowlist set, we skip this check
	}

	for _, needle := range needles {
		needle := standerdiseListItem(needle)
		for i := range allowed { // foreach allowed item
			if os.Getenv("ALLOWLIST_STRICT") == "true" {
				// strict matching. don't match subdomains
				if needle == allowed[i].allow {
					if os.Getenv("DEBUG") == "true" {
						Printy(allowed[i].allow+" found in allowlist", 3)
					}
					return true
				}
			} else {
				// allow fuzzy matching
				// technically, this could be bypassed with: knary.tld.permitted.knary.tld and
				if stringContains(needle, allowed[i].allow) {
					if os.Getenv("DEBUG") == "true" {
						Printy(allowed[i].allow+" found in allowlist", 3)
					}
					return true
				}
			}
		}
	}
	return false
}

func inBlacklist(needles ...string) bool {
	for _, needle := range needles {
		if denied.searchD(needle) {
			denied.updateD(needle) // found!

			if os.Getenv("DEBUG") == "true" {
				logger("INFO", "Found "+needle+" in denylist")
				Printy("Found "+needle+" in denylist", 3)
			}
			return true
		}
	}
	return false
}

func checkLastHit() bool { // this runs once a day
	for subdomain := range denied.deny {
		expiryDate := denied.deny[subdomain].AddDate(0, 0, 14)

		if time.Now().After(expiryDate) { // let 'em know it's old
			msg := "Denied item `" + subdomain + "` hasn't had a hit in >14 days. Consider removing it."
			go sendMsg(":wrench: " + msg + " Configure `DENYLIST_ALERTING` to supress.")
			logger("INFO", msg)
			Printy(msg, 1)
		}
	}

	if os.Getenv("DEBUG") == "true" {
		logger("INFO", "Checked denylist...")
		Printy("Checked for old denylist items", 3)
	}

	return true
}
