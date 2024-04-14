package libknary

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestSendMsg(t *testing.T) {
	// Create a test server to capture HTTP requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request URL and method
		switch r.URL.String() {
		case "/":
			if r.Method != http.MethodPost {
				t.Errorf("Expected POST request for Slack webhook, got %s", r.Method)
			}
		default:
			t.Errorf("Unexpected request to URL: %s", r.URL.String())
		}
	}))

	defer server.Close()

	// Override the Slack webhook URL with the test server URL
	os.Setenv("SLACK_WEBHOOK", server.URL)

	// SLACK_WEBHOOK is set
	sendMsg("Test message for Slack")
}
