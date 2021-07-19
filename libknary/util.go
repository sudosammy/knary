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
	"time"
//	"sync"

	"github.com/blang/semver/v4"
)

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

func stringContains(stringA string, stringB string) bool {
	return strings.Contains(
		strings.ToLower(stringA),
		strings.ToLower(stringB),
	)
}

func splitPort(ipaddr string) (string, int) {
	// spit the IP address to remove the port
	// this is almost certainly badly broken
	ipSlice := strings.Split(ipaddr, ":")
	ipSlice = ipSlice[:len(ipSlice)-1]
	ipaddrNoPort := strings.Join(ipSlice[:], ",")

	portSlice := strings.Split(ipaddr, ":")
	portSlice = portSlice[len(portSlice)-1:]

	onlyPortSlice := strings.Join(portSlice[:], ",")
	onlyPort, _ := strconv.Atoi(onlyPortSlice)

	if IsIP(ipaddrNoPort) {
		return ipaddrNoPort, onlyPort
	} else {
		return "", 0
	}
}

func specialMessage(version string) {
	// check for any special messages to include
	// running, err := semver.Make(version)

	// if err != nil {
	// 	Printy("Could not check for messages: " + err.Error(), 2)
	// 	return false, err
	// }

	// c := &http.Client{
	// 	Timeout: 10 * time.Second,
	// }
	// response, err := c.Get("https://raw.githubusercontent.com/sudosammy/knary/master/MESSAGES")

	// if err != nil {
	// 	Printy("Could not check for messages: " + err.Error(), 2)
	// 	return false, err
	// }
	// we want to check github for a file which includes a semver and a message
	// something like <3.3.0 "thi is the message"
	// this function will run daily and if any messages match our version number
	// we print to the webhook
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

// map for blacklist
// TODO. this is lol
// you want to match on domain
// so domain should be the map key
// and the struct should contain `mutex *sync.RWMutex`
type blacklist struct {
	domain  string
	lastHit time.Time
}

var blacklistMap = map[int]blacklist{}
var blacklistCount = 0

func LoadBlacklist() (bool, error) {
	if os.Getenv("BLACKLIST_FILE") != "" {
		// deprecation warning
		Printy("The environment variable \"DENYLIST_FILE\" has superseded \"BLACKLIST_FILE\". Please update your configuration.", 2)
	}
	// load blacklist file into struct on startup
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

	for scanner.Scan() { // foreach blacklist item
		blacklistMap[blacklistCount] = blacklist{scanner.Text(), time.Now()} // add to struct
		blacklistCount++
	}

	Printy("Monitoring "+strconv.Itoa(blacklistCount)+" items in denylist", 1)
	logger("INFO", "Monitoring "+strconv.Itoa(blacklistCount)+" items in denylist")
	return true, nil
}

func checkLastHit() bool { // this runs once a day
	if len(blacklistMap) != 0 {
		// iterate through blacklist and look for items >14 days old
		for i := range blacklistMap { // foreach blacklist item
			expiryDate := blacklistMap[i].lastHit.AddDate(0, 0, 14)

			if time.Now().After(expiryDate) { // let 'em know it's old
				msg := "Denied item `" + blacklistMap[i].domain + "` hasn't had a hit in >14 days. Consider removing it."
				go sendMsg(":wrench: " + msg + " Configure `DENYLIST_ALERTING` to supress.")
				logger("INFO", msg)
				Printy(msg, 1)
			}
		}

		if os.Getenv("DEBUG") == "true" {
			logger("INFO", "Checked denylist...")
			Printy("Checked for old denylist items", 3)
		}
	}
	return true
}

func inBlacklist(needles ...string) bool {
	// this function should not require nested for loops!
	// https://play.golang.org/p/JGZ7mN0-U-
	for _, needle := range needles {
		for i := range blacklistMap { // foreach blacklist item
			if stringContains(needle, blacklistMap[i].domain) && !stringContains(needle, "."+blacklistMap[i].domain) {
				// matches blacklist.domain or 1.1.1.1 but not x.blacklist.domain
				updBL := blacklistMap[i]
				updBL.lastHit = time.Now() // update last hit
				// lock this operation to prevent race conditions
				//c.mutex.Lock()
				blacklistMap[i] = updBL
				//c.mutex.Unlock()

				if os.Getenv("DEBUG") == "true" {
					Printy(blacklistMap[i].domain+" found in denylist", 3)
				}
				return true
			}
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
	// runs weekly (and on launch) to let people know we're alive (and show them the blacklist)
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

	// print blacklisted items
	beatMsg += strconv.Itoa(blacklistCount) + " denied domains: \n"
	beatMsg += "------------------------\n"
	for i := range blacklistMap { // foreach blacklist item
		beatMsg += strings.ToLower(blacklistMap[i].domain) + "\n"
	}
	beatMsg += "------------------------\n\n"

	// print usage domains
	if os.Getenv("HTTP") == "true" && (os.Getenv("TLS_CRT") == "" || os.Getenv("TLS_KEY") == "") {
		beatMsg += "Listening for http://*." + os.Getenv("CANARY_DOMAIN") + " requests\n"
	} else {
		beatMsg += "Listening for http(s)://*." + os.Getenv("CANARY_DOMAIN") + " requests\n"
	}
	if os.Getenv("DNS") == "true" {
		beatMsg += "Listening for *." + os.Getenv("CANARY_DOMAIN") + " DNS requests\n"
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
