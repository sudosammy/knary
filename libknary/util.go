package libknary

import (
	"bufio"
	"net/http"
	"os"
	"strings"

	"github.com/blang/semver"
)

func stringContains(stringA string, stringB string) bool {
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
		return false
	}

	response, err := http.Get(githubVersion)

	if err != nil {
		updFail := "Could not check for updates: " + err.Error()
		Printy(updFail, 2)
		logger(updFail)
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
			updMsg := ":warning: Your version of knary is *" + version + "* & the latest is *" + current.String() + "* - upgrade your binary here: " + githubURL
			Printy(updMsg, 2)
			logger(updMsg)
			go sendMsg(updMsg)
			return true
		}
	}

	return false
}

func inBlacklist(needles ...string) bool {
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

	for scanner.Scan() { // foreach blacklist item
		for _, needle := range needles { // foreach needle
			if strings.Contains(needle, scanner.Text()) && !strings.Contains(needle, "."+scanner.Text()) {
				// matches blacklist.domain or 1.1.1.1 but not x.blacklist.domain
				if os.Getenv("DEBUG") == "true" {
					Printy(scanner.Text()+" found in blacklist", 3)
				}
				return true
			}
		}		
	}
	return false
}
