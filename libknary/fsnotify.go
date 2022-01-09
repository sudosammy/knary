package libknary

// Eventually this will support deny/allowlists too

import (
	"log"
	"os"
	"time"

	"github.com/radovskyb/watcher"
	cmd "github.com/sudosammy/knary/libknary/lego"
)

func TLSmonitor(restart chan bool) {
	w := watcher.New()
	// get filepath of certificate store
	certDir := cmd.GetCertPath()
	// Only notify write events
	w.FilterOps(watcher.Write)

	go func() {
		for {
			select {
			case event := <-w.Event:
				if event.Op == watcher.Write && event.IsDir() {
					continue // skip on folder changes
				}
				logger("INFO", "Server will reload on next HTTPS request to knary")
				if os.Getenv("DEBUG") == "true" {
					Printy("Server will reload on next HTTPS request to knary", 3)
				}
				restart <- true
			case err := <-w.Error:
				logger("ERROR", err.Error())
				GiveHead(2)
				log.Fatal(err)
			case <-w.Closed:
				return
			}
		}
	}()

	// watch the certificate directory for changes.
	if err := w.Add(certDir); err != nil {
		logger("ERROR", err.Error())
		GiveHead(2)
		log.Fatal(err)
	}

	// start the watching process - it'll check for changes every second.
	if err := w.Start(time.Second * 1); err != nil {
		log.Fatalln(err)
	}
}
