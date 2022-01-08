package libknary

import (
	"os"
	"time"
)

func dailyTasks(version string, githubVersion string, githubURL string) bool {
	logger("INFO", "Daily maintenance tasks running")
	// check for updates
	CheckUpdate(version, githubVersion, githubURL)

	// flag any denied items that haven't had a hit in >14 days
	if os.Getenv("DENYLIST_ALERTING") != "false" {
		checkLastHit()
	}

	// if HTTPS knary is operating, check certificate expiry
	if os.Getenv("TLS_CRT") != "" && os.Getenv("TLS_KEY") != "" {
		_, _ = CheckTLSExpiry(30)
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
