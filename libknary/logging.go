package libknary

import (
	"os"
	"time"
)

func logger(message string) {
	if os.Getenv("LOG_FILE") != "" {
		f, err := os.OpenFile(os.Getenv("LOG_FILE"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)

		if err != nil {
			Printy(err.Error(), 2)
		}

		defer f.Close()

		// add newline if not present
		lastChar := message[len(message)-1:]
		var toLog string

		if lastChar != "\n" {
			toLog = message + "\n"
		} else {
			toLog = message
		}

		// log with timestamp
		if _, err = f.WriteString("[" + time.Now().Format(time.RFC850) + "]\n" + toLog); err != nil {
			Printy(err.Error(), 2)
		}
	}
}
