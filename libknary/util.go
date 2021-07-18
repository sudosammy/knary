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
type blacklist struct {
	domain  string
	lastHit time.Time
}

var blacklistMap = map[int]blacklist{}
var blacklistCount = 0

func LoadBlacklist() (bool, error) {
	// load blacklist file into struct on startup
	if _, err := os.Stat(os.Getenv("BLACKLIST_FILE")); os.IsNotExist(err) {
		return false, err
	}

	blklist, err := os.Open(os.Getenv("BLACKLIST_FILE"))
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

	Printy("Monitoring "+strconv.Itoa(blacklistCount)+" items in blacklist", 1)
	logger("INFO", "Monitoring "+strconv.Itoa(blacklistCount)+" items in blacklist")
	return true, nil
}

func checkLastHit() bool { // this runs once a day
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

		if os.Getenv("DEBUG") == "true" {
			logger("INFO", "Checked blacklist...")
			Printy("Checked for old blacklist items", 3)
		}
	}
	return true
}

func inBlacklist(needles ...string) bool {
	for _, needle := range needles {
		for i := range blacklistMap { // foreach blacklist item
			if stringContains(needle, blacklistMap[i].domain) && !stringContains(needle, "."+blacklistMap[i].domain) {
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

func CheckTLSExpiry(days int) bool {
	renew, expiry := needRenewal(days)

	if os.Getenv("DEBUG") == "true" {
		Printy("TLS certificate expires in " + strconv.Itoa(expiry) + " days.", 3)
	}

	if renew {
		logger("INFO", "TLS certificate expires in " + strconv.Itoa(expiry) + " days.")
		Printy("TLS certificate expires in " + strconv.Itoa(expiry) + " days.", 3)
		if (os.Getenv("LETS_ENCRYPT") != "") {
			Printy("Attempting Let's Encrypt renewal...", 3)
			renewLetsEncrypt()
		}
	}

	if expiry <= 20 { // if cert expires in 20 days or less
		certMsg := "The TLS certificate for `" + os.Getenv("CANARY_DOMAIN") + "` expires in " + strconv.Itoa(expiry) + " days."
		Printy(certMsg, 2)
		logger("WARNING", certMsg)
		go sendMsg(":lock: " + certMsg)
		return true
	}

	return false
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

	// print uptime
	if day == 1 {
		beatMsg += "Uptime: " + strconv.Itoa(day) + " day\n\n"
	} else {
		beatMsg += "Uptime: " + strconv.Itoa(day) + " days\n\n"
	}

	// print blacklisted items
	beatMsg += strconv.Itoa(blacklistCount) + " blacklisted domains: \n"
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