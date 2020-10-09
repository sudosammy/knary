package libknary

import (
	"os"
	"time"
	"crypto/tls"
)

func dailyTasks(version string, githubVersion string, githubURL string) bool {
	// check for updates
	CheckUpdate(version, githubVersion, githubURL)

	// if blacklist alerting is enabled, flag any old blacklist items
	if os.Getenv("BLACKLIST_ALERTING") == "" || os.Getenv("BLACKLIST_ALERTING") == "true" {
		CheckLastHit()
	}

	// if HTTP knary is operating, check certificate expiry
	if os.Getenv("HTTP") == "true" {
		// this could be done better
		// there's probably not a situation where we want to enforce certificate verification
		conf := &tls.Config {
			InsecureSkipVerify: true,
		}
		CheckTLSExpiry(os.Getenv("CANARY_DOMAIN"), conf)
	}

	// log knary usage
	UsageStats(version)

	return true
}

func StartMaintenance(version string, githubVersion string, githubURL string) {
	// https://stackoverflow.com/questions/16466320/is-there-a-way-to-do-repetitive-tasks-at-intervals-in-golang
	dailyTicker := time.NewTicker(24 * time.Hour)
	hbTicker := time.NewTicker(24 * 7 * time.Hour) // once a week
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-dailyTicker.C:
				dailyTasks(version, githubVersion, githubURL)
			case <-hbTicker.C:
				HeartBeat(version, false)
			case <-quit:
				dailyTicker.Stop()
				hbTicker.Stop()
				return
			}
		}
	}()
}
