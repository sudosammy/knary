package libknary

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

func sendMsg(msg string) {
	// closes https://github.com/sudosammy/knary/issues/20
	re := regexp.MustCompile(`\r?\n`)
	msg = re.ReplaceAllString(msg, "\\n")
	msg = strings.ReplaceAll(msg, "\"", "\\\"")

	if os.Getenv("SLACK_WEBHOOK") != "" {
		jsonMsg := []byte(`{"username":"knary","icon_emoji":":bird:","text":"` + msg + `"}`)
		_, err := http.Post(os.Getenv("SLACK_WEBHOOK"), "application/json", bytes.NewBuffer(jsonMsg))

		if err != nil {
			Printy(err.Error(), 2)
		}
	}

	if os.Getenv("PUSHOVER_TOKEN") != "" && os.Getenv("PUSHOVER_USER") != "" {
		jsonMsg := []byte(`{"token":"` + os.Getenv("PUSHOVER_TOKEN") + `","user":"` + os.Getenv("PUSHOVER_USER") + `","message":"` + msg + `"}`)
		_, err := http.Post("https://api.pushover.net/1/messages.json/", "application/json", bytes.NewBuffer(jsonMsg))

		if err != nil {
			Printy(err.Error(), 2)
		}
	}

	if os.Getenv("LARK_WEBHOOK") != "" {
		re = regexp.MustCompile("```\\n?")
		msg = re.ReplaceAllString(msg, "")

		jsonMsg := []byte("{\n")

		if larkSecret := os.Getenv("LARK_SECRET"); larkSecret != "" {
			// Generate signature
			timestamp := time.Now().Unix()
			sig, err := SignLark(os.Getenv("LARK_SECRET"), timestamp)
			if err != nil {
				Printy(err.Error(), 2)
			}

			// Add fields to payload
			sigFields := fmt.Sprintf(""+
				"    \"timestamp\": \"%d\",\n"+
				"    \"sign\": \"%s\",\n", timestamp, sig)

			jsonMsg = append(jsonMsg, sigFields...)
		}

		// Escape hell. Probably could have just backticked lol.
		postBody := fmt.Sprintf(""+
			"    \"msg_type\": \"post\",\n"+
			"    \"content\": {\n"+
			"        \"post\": {\n"+
			"            \"en_us\": {\n"+
			"                \"title\": \"Knary Triggered 🐦\",\n"+
			"                \"content\": [\n"+
			"                    [\n"+
			"                        {\n"+
			"                            \"tag\": \"text\",\n"+
			"                            \"text\": \"%s\"\n"+
			"                        }\n"+
			"                    ]\n"+
			"                ]\n"+
			"            }\n"+
			"        }\n"+
			"    }\n"+
			"}", msg)

		jsonMsg = append(jsonMsg, postBody...)

		_, err := http.Post(os.Getenv("LARK_WEBHOOK"), "application/json", bytes.NewBuffer(jsonMsg))

		if err != nil {
			Printy(err.Error(), 2)
		}
	}

	if os.Getenv("DISCORD_WEBHOOK") != "" {
		jsonMsg := []byte(`{"username":"knary","text":"` + msg + `"}`)
		_, err := http.Post(os.Getenv("DISCORD_WEBHOOK")+"/slack", "application/json", bytes.NewBuffer(jsonMsg))

		if err != nil {
			Printy(err.Error(), 2)
		}
	}

	if os.Getenv("TEAMS_WEBHOOK") != "" {
		// swap ``` with <pre> for MS teams :face-with-rolling-eyes:
		msg = strings.Replace(msg, "```", "</pre>", 2)
		msg = strings.Replace(msg, "</pre>", "<pre>", 1)

		jsonMsg := []byte(`{"text":"` + msg + `"}`)
		_, err := http.Post(os.Getenv("TEAMS_WEBHOOK"), "application/json", bytes.NewBuffer(jsonMsg))

		if err != nil {
			Printy(err.Error(), 2)
		}
	}

	// should be simple enough to add support for other webhooks here
}
