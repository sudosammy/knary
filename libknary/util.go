package libknary

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blang/semver/v4"
)

// map for denylist
type blacklist struct {
	mutex sync.Mutex
	deny  map[string]time.Time
}

var denied = blacklist{deny: make(map[string]time.Time)}
var blacklistCount = 0

// add or update a denied domain/IP
func (a *blacklist) updateD(term string) bool {
	if term == "" {
		return false // would happen if there's no X-Forwarded-For header
	}
	item := standerdiseDenylistItem(term)
	a.mutex.Lock()
	//a.deny[item] = time.Now()
	a.deny[item] = time.Now()
	a.mutex.Unlock()
	return true
}

// search for a denied domain/IP
func (a *blacklist) searchD(term string) bool {
	item := standerdiseDenylistItem(term)
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.deny[item]; ok {
		return true // found!
	}
	return false
}

func standerdiseDenylistItem(term string) string {
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

// https://github.com/dsanader/govalidator/blob/master/validator.go
func IsIP(str string) bool {
	return net.ParseIP(str) != nil
}
func IsIPv4(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ".")
}
func IsIPv6(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ":")
}

func stringContains(haystack string, needle string) bool {
	return strings.Contains(
		strings.ToLower(haystack),
		strings.ToLower(needle),
	)
}

// https://rosettacode.org/wiki/Parse_an_IP_Address#Go
func splitPort(s string) (string, int) {
	ip := net.ParseIP(s)
	var port string

	if ip == nil {
		var host string
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			return "", 0
		}

		if port != "" {
			// This check only makes sense if service names are not allowed
			if _, err = strconv.ParseUint(port, 10, 16); err != nil {
				return "", 0
			}
		}
		ip = net.ParseIP(host)
	}

	if ip == nil {
		return "", 0
	} else {
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
	}

	stringIP := ip.String()
	intPort, _ := strconv.Atoi(port)

	if IsIP(stringIP) {
		return stringIP, intPort
	} else {
		return "", 0
	}
}

func CheckUpdate(version string, githubVersion string, githubURL string) (bool, error) { // this runs once a day
	running, err := semver.Make(version)

	if err != nil {
		updFail := "Could not check for updates: " + err.Error()
		Printy(updFail, 2)
		logger("WARNING", updFail)
		go sendMsg(":warning: " + updFail)
		return false, err
	}

	c := &http.Client{
		Timeout: 10 * time.Second,
	}
	response, err := c.Get(githubVersion)

	if err != nil {
		updFail := "Could not check for updates: " + err.Error()
		Printy(updFail, 2)
		logger("WARNING", updFail)
		go sendMsg(":warning: " + updFail)
		return false, err
	}

	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body) // refusing to import ioutil

	for scanner.Scan() { // foreach line
		current, err := semver.Make(scanner.Text())

		if err != nil {
			updFail := "Could not check for updates. GitHub response !semver format"
			Printy(updFail, 2)
			logger("WARNING", updFail)
			return false, err
		}

		if running.LT(current) == true {
			updMsg := "Your version of knary is *" + version + "* & the latest is *" + current.String() + "* - upgrade your binary here: " + githubURL
			Printy(updMsg, 2)
			logger("WARNING", updMsg)
			go sendMsg(":warning: " + updMsg)
			return true, nil
		}
	}

	if os.Getenv("DEBUG") == "true" {
		logger("INFO", "Checked for updates...")
		Printy("Checked for updates", 3)
	}
	return false, nil
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
			blacklistCount++
		}
	}

	Printy("Monitoring "+strconv.Itoa(blacklistCount)+" items in denylist", 1)
	logger("INFO", "Monitoring "+strconv.Itoa(blacklistCount)+" items in denylist")
	return true, nil
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

func CheckTLSExpiry(days int) (bool, int) {
	if os.Getenv("TLS_CRT") != "" && os.Getenv("TLS_KEY") != "" {
		renew, expiry := needRenewal(days)

		if renew {
			Printy("TLS certificate expires in "+strconv.Itoa(expiry)+" days", 3)
			if os.Getenv("LETS_ENCRYPT") != "" {
				renewLetsEncrypt()
			}
		}

		if expiry <= 20 { // if cert expires in 20 days or less
			certMsg := "The TLS certificate for `" + os.Getenv("CANARY_DOMAIN") + "` expires in " + strconv.Itoa(expiry) + " days."
			Printy(certMsg, 2)
			logger("WARNING", certMsg)
			go sendMsg(":lock: " + certMsg)
			return true, expiry
		}

		return false, expiry
	}

	if os.Getenv("DEBUG") == "true" {
		Printy("CheckTLSExpiry was called without any certificates being loaded...", 2)
	}

	return false, 0
}

func HeartBeat(version string, firstrun bool) (bool, error) {
	// runs weekly (and on launch) to let people know we're alive (and show them the denylist)
	beatMsg := "```"
	if firstrun {
		beatMsg += ` __                           
|  |--.-----.---.-.----.--.--.
|    <|     |  _  |   _|  |  |
|__|__|__|__|___._|__| |___  |` + "\n"
		beatMsg += ` @sudosammy     v` + version + ` `
		beatMsg += `|_____|`
		beatMsg += "\n\n"
	} else {
		beatMsg += "❤️ Heartbeat (v" + version + ") ❤️\n"
	}

	// print TLS cert expiry
	if os.Getenv("TLS_CRT") != "" && os.Getenv("TLS_KEY") != "" {
		_, expiry := needRenewal(30)
		if expiry == 1 {
			beatMsg += "Certificate expiry in: " + strconv.Itoa(expiry) + " day\n"
		} else {
			beatMsg += "Certificate expiry in: " + strconv.Itoa(expiry) + " days\n"
		}
	}

	// print uptime
	if day == 1 {
		beatMsg += "Uptime: " + strconv.Itoa(day) + " day\n\n"
	} else {
		beatMsg += "Uptime: " + strconv.Itoa(day) + " days\n\n"
	}

	// print denied items
	beatMsg += strconv.Itoa(blacklistCount) + " denied subdomains / IPs: \n"
	beatMsg += "------------------------\n"
	for subdomain := range denied.deny {
		beatMsg += subdomain + "\n"
	}
	beatMsg += "------------------------\n\n"

	// print usage domains
	if os.Getenv("HTTP") == "true" && (os.Getenv("TLS_CRT") == "" || os.Getenv("TLS_KEY") == "") {
		beatMsg += "Listening for http://*." + os.Getenv("CANARY_DOMAIN") + " requests\n"
	} else {
		beatMsg += "Listening for http(s)://*." + os.Getenv("CANARY_DOMAIN") + " requests\n"
	}
	if os.Getenv("DNS") == "true" {
		if os.Getenv("DNS_SUBDOMAIN") != "" { 
			beatMsg += "Listening for *." + os.Getenv("DNS_SUBDOMAIN")+"."+os.Getenv("CANARY_DOMAIN") + " DNS requests\n"
		} else {
			beatMsg += "Listening for *." + os.Getenv("CANARY_DOMAIN") + " DNS requests\n"
		}
	}
	if os.Getenv("BURP_DOMAIN") != "" {
		beatMsg += "Working in collaborator compatibility mode on subdomain *." + os.Getenv("BURP_DOMAIN") + "\n"
	}
	beatMsg += "```"

	go sendMsg(beatMsg)

	if os.Getenv("DEBUG") == "true" {
		logger("INFO", "Sent heartbeat...")
		Printy("Sent heartbeat message", 3)
	}

	return true, nil
}

// https://www.feishu.cn/hc/en-US/articles/360024984973-Bot-Use-bots-in-groups
func SignLark(secret string, timestamp int64) (string, error) {
	//timestamp + key as sha256, then base64 encode
	stringToSign := fmt.Sprintf("%v", timestamp) + "\n" + secret

	var data []byte
	h := hmac.New(sha256.New, []byte(stringToSign))
	_, err := h.Write(data)
	if err != nil {
		return "", err
	}

	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return signature, nil
}

func fileExists(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	} else if err != nil {
		logger("ERROR", err.Error())
		Printy(err.Error(), 2)
		return false
	}
	return true
}
