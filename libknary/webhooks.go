package libknary

import (
	"bytes"
	"net/http"
	"os"
)

func sendMsg(msg string) {
	jsonMsg := []byte(`{"username":"knary","icon_emoji":":bird:","text":"` + msg + `"}`)
	_, err := http.Post(os.Getenv("SLACK_WEBHOOK"), "application/json", bytes.NewBuffer(jsonMsg))

	if err != nil {
		Printy(err.Error(), 2)
	}
}
