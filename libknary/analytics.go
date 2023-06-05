package libknary

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"
)

/*
This function collects basic telemetry to track knary usage.
It does NOT collect anything that could be tied back to you easily; however, does take a SHA256 hash of your knary domain name.
If you have any thoughts about knary you can contact me on Twitter: @sudosammy or GitHub: https://github.com/sudosammy/knary

You can make the following variable an empty string to sinkhole analytics.
*/
var trackingDomain = "https://knary.sam.ooo"

type features struct {
	DEBUG             bool `json:"debug"`
	DNS               bool `json:"dns"`
	DNS_SUBDOMAIN     bool `json:"dns_subdomain"` // True/False
	HTTP              bool `json:"http"`
	HTTP_FULL         bool `json:"full_http_request"`
	BURP              bool `json:"burp"`
	REV_PROXY         bool `json:"reverse_proxy"`
	ALLOW             int  `json:"allowlist"` // Count of items in
	ALLOW_STRICT      bool `json:"allowlist_strict"`
	DENY              int  `json:"denylist"` // Count of items in
	LE                bool `json:"lets_encrypt"`
	TLS               bool `json:"tls_certs"`
	LOGS              bool `json:"logs"`
	ZONE_FILE         int  `json:"zone_file"` // Count of items in
	DENYLIST_ALERTING bool `json:"no_denylist_alert"`
	NO_HEARTBEAT      bool `json:"no_heartbeat"`
	NO_UPDATES        bool `json:"no_update_alert"`
	NO_CERT_EXPIRY    bool `json:"no_cert_expiry_alert"`
}

type webhooks struct {
	SLACK    bool `json:"slack"`
	DISCORD  bool `json:"discord"`
	PUSHOVER bool `json:"pushover"`
	TEAMS    bool `json:"teams"`
	LARK     bool `json:"lark"`
	TELEGRAM bool `json:"telegram"`
}

type analy struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	basicInfo `json:"basic"`
	features  `json:"features"`
	webhooks  `json:"webhooks"`
}

type basicInfo struct {
	OS       string `json:"os"`
	Uptime   int    `json:"uptime"`
	Version  string `json:"version"`
	Offset   int    `json:"offset"`
	Timezone string `json:"tz"`
}

var day = 0

func UsageStats(version string) bool {
	if os.Getenv("CANARY_DOMAIN") == "" || trackingDomain == "" {
		return false
	}

	knaryID := sha256.New()
	_, _ = knaryID.Write([]byte(os.Getenv("CANARY_DOMAIN")))
	anonKnaryID := hex.EncodeToString(knaryID.Sum(nil))

	ts := time.Now().UTC() // UTC timestamp
	utcTimestamp := ts.Format("2006-01-02 15:04")
	tz, offset := time.Now().Zone() // local timezone

	day++ // keep track of uptime
	debug, _ := strconv.ParseBool(os.Getenv("DEBUG"))
	dnsKnary, _ := strconv.ParseBool(os.Getenv("DNS"))
	httpKnary, _ := strconv.ParseBool(os.Getenv("HTTP"))
	fullHttp, _ := strconv.ParseBool(os.Getenv("FULL_HTTP_REQUEST"))
	allowStrict, _ := strconv.ParseBool(os.Getenv("ALLOWLIST_STRICT"))
	denylistAlertingInverted, _ := strconv.ParseBool(os.Getenv("DENYLIST_ALERTING"))
	denylistAlerting := !denylistAlertingInverted
	heartbeat, _ := strconv.ParseBool(os.Getenv("NO_HEARTBEAT_ALERT"))
	checkUpdates, _ := strconv.ParseBool(os.Getenv("NO_UPDATES_ALERT"))
	checkCertExpiry, _ := strconv.ParseBool(os.Getenv("NO_CERT_EXPIRY_ALERT"))

	dnsSubdomain := false
	if len(os.Getenv("DNS_SUBDOMAIN")) > 0 {
		dnsSubdomain = true
	}

	burp := false
	if len(os.Getenv("BURP_DOMAIN")) > 0 {
		burp = true
	}

	revProxy := false
	if len(os.Getenv("REVERSE_PROXY_DOMAIN")) > 0 {
		revProxy = true
	}

	letsEnc := false
	if len(os.Getenv("LETS_ENCRYPT")) > 0 {
		letsEnc = true
	}

	tlsCerts := false
	if len(os.Getenv("TLS_CRT")) > 0 {
		tlsCerts = true
	}

	logFile := false
	if len(os.Getenv("LOG_FILE")) > 0 {
		logFile = true
	}

	// webhooks
	slack := false
	if len(os.Getenv("SLACK_WEBHOOK")) > 0 {
		slack = true
	}

	discord := false
	if len(os.Getenv("DISCORD_WEBHOOK")) > 0 {
		discord = true
	}

	pushover := false
	if len(os.Getenv("PUSHOVER_TOKEN")) > 0 {
		pushover = true
	}

	teams := false
	if len(os.Getenv("TEAMS_WEBHOOK")) > 0 {
		teams = true
	}

	lark := false
	if len(os.Getenv("LARK_WEBHOOK")) > 0 {
		lark = true
	}

	telegram := false
	if len(os.Getenv("TELEGRAM_CHATID")) > 0 {
		telegram = true
	}

	jsonValues, err := json.Marshal(&analy{
		anonKnaryID,
		utcTimestamp,
		basicInfo{
			runtime.GOOS,
			day,
			version,
			(offset / 60 / 60),
			tz,
		},
		features{
			debug,
			dnsKnary,
			dnsSubdomain,
			httpKnary,
			fullHttp,
			burp,
			revProxy,
			allowCount,
			allowStrict,
			denyCount,
			letsEnc,
			tlsCerts,
			logFile,
			zoneCounter,
			denylistAlerting,
			heartbeat,
			checkUpdates,
			checkCertExpiry,
		},
		webhooks{
			slack,
			discord,
			pushover,
			teams,
			lark,
			telegram,
		},
	})

	if err != nil {
		if os.Getenv("DEBUG") == "true" {
			Printy(err.Error(), 3)
		}
		return false
	}

	c := &http.Client{
		Timeout: 10 * time.Second,
	}
	_, err = c.Post(trackingDomain, "application/json", bytes.NewBuffer(jsonValues))

	if err != nil {
		if os.Getenv("DEBUG") == "true" {
			Printy(err.Error(), 3)
		}
		return false
	}

	return true
}
