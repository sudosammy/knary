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

// domains to monitor
var domains []string

func LoadDomains(domainList string) error {
	prepareSplit := strings.ReplaceAll(domainList, " ", "")
	domains = strings.Split(prepareSplit, ",")
	return nil
}

func GetDomains() []string {
	return domains
}

func GetFirstDomain() string {
	return domains[0]
}

func returnSuffix(lookupVal string) (bool, string) {
	// we return bool for the http handleRequest()
	// we return string for the dns SOA and NS responses
	for _, suffix := range domains {
		if stringContains(lookupVal, suffix) || stringContains(lookupVal, suffix+".") {
			return true, suffix
		}
	}
	return false, ""
}

func isRoot(lookupVal string) (bool, error) {
	for _, prefix := range domains {
		if strings.HasPrefix(strings.ToLower(lookupVal), strings.ToLower(prefix+".")) {
			return true, nil
		}
	}
	return false, nil
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
		var err error
		host, port, err = net.SplitHostPort(s)
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

		if os.Getenv("NO_UPDATES_ALERT") == "true" {
			go sendMsg(":warning: " + updFail)
		}

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

		if os.Getenv("NO_UPDATES_ALERT") == "true" {
			go sendMsg(":warning: " + updFail)
		}

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

		if running.LT(current) {
			updMsg := "Your version of knary is *" + version + "* & the latest is *" + current.String() + "* - upgrade your binary here: " + githubURL
			Printy(updMsg, 2)
			logger("WARNING", updMsg)

			if os.Getenv("NO_UPDATES_ALERT") == "true" {
				go sendMsg(":warning: " + updMsg)
			}

			return true, nil
		}
	}

	if os.Getenv("DEBUG") == "true" {
		logger("INFO", "Checked for updates...")
		Printy("Checked for updates", 3)
	}
	return false, nil
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

			if os.Getenv("NO_CERT_EXPIRY_ALERT") == "true" {
				go sendMsg(":lock: " + certMsg)
			}

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

	// print allowed items (if any)
	if allowCount > 0 {
		beatMsg += strconv.Itoa(allowCount) + " allowed subdomains, User-Agents, IPs: \n"
		if os.Getenv("ALLOWLIST_STRICT") == "true" {
			beatMsg += "(Operating in strict mode) \n"
		}
		beatMsg += "------------------------\n"
		for i := range allowed {
			beatMsg += allowed[i].allow + "\n"
		}
		beatMsg += "------------------------\n\n"
	}

	// print denied items (if any)
	if denyCount > 0 {
		beatMsg += strconv.Itoa(denyCount) + " denied subdomains, User-Agents, IPs: \n"
		beatMsg += "------------------------\n"
		for subdomain := range denied.deny {
			beatMsg += subdomain + "\n"
		}
		beatMsg += "------------------------\n\n"
	}

	// print usage domains
	if os.Getenv("HTTP") == "true" && (os.Getenv("TLS_CRT") == "" || os.Getenv("TLS_KEY") == "") {
		for _, cdomain := range GetDomains() {
			beatMsg += "Listening for http://*." + cdomain + " requests\n"
		}
	} else if os.Getenv("HTTP") == "true" && (os.Getenv("TLS_CRT") != "" && os.Getenv("TLS_KEY") != "") {
		for _, cdomain := range GetDomains() {
			beatMsg += "Listening for http(s)://*." + cdomain + " requests\n"
		}
	}
	if os.Getenv("DNS") == "true" {
		if os.Getenv("DNS_SUBDOMAIN") != "" {
			for _, cdomain := range GetDomains() {
				beatMsg += "Listening for *." + os.Getenv("DNS_SUBDOMAIN") + "." + cdomain + " DNS requests\n"
			}
		} else {
			for _, cdomain := range GetDomains() {
				beatMsg += "Listening for *." + cdomain + " DNS requests\n"
			}
		}
	}
	if os.Getenv("BURP_DOMAIN") != "" {
		beatMsg += "(Deprecated) Working in collaborator compatibility mode on subdomain *." + os.Getenv("BURP_DOMAIN") + "\n"
	}
	if os.Getenv("REVERSE_PROXY_DOMAIN") != "" {
		beatMsg += "Reverse proxy enabled on requests to: *." + os.Getenv("REVERSE_PROXY_DOMAIN") + "\n"
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

func IsDeprecated(old string, new string, version string) {
	msg := "`" + old + "`" + " is deprecated. It will be removed in `" + version + "`. Change to: `" + new + "`"
	logger("WARNING", msg)
	Printy(msg, 3)
	go sendMsg(":warning: " + msg)
}
