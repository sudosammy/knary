package libknary

// Eventually this will support deny/allowlists too

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/radovskyb/watcher"
)

func TLSmonitor(restart chan bool) {
	w := watcher.New()

	// get filepath of certificate store
	certDir := filepath.Dir(os.Getenv("TLS_KEY"))

	// Only notify write events.
	w.FilterOps(watcher.Write)

	go func() {
		for {
			select {
			case event := <-w.Event:
				if event.Op == watcher.Write && event.IsDir() {
					continue // skip on folder changes
				}
				logger("INFO", "Server will reload on next HTTPS request to knary")
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

	// Watch the certificate directory for changes.
	if err := w.Add(certDir); err != nil {
		logger("ERROR", err.Error())
		GiveHead(2)
		log.Fatal(err)
	}

	// Start the watching process - it'll check for changes every 1000ms.
	if err := w.Start(time.Millisecond * 1000); err != nil {
		log.Fatalln(err)
	}
}
