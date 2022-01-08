package libknary

// Thanks https://medium.com/@skdomino/watch-this-file-watching-in-go-5b5a247cf71f
// Eventually this will support deny/allowlists too

import (
	"log"
	"os"

	"github.com/fsnotify/fsnotify"
)

func TLSmonitor(restart chan bool) {
	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger("ERROR", err.Error())
		GiveHead(2)
		log.Fatal(err)
	}
	defer watcher.Close()
	done := make(chan bool)

	go func() {
		for {
			select {
			// watch for events
			case <-watcher.Events:
				// trigger reload of certificates!
				msg := "TLS key changed! The TLS listener will be restarted on next HTTPS request to knary."
				logger("INFO", msg)
				Printy(msg, 3)
				go sendMsg(msg + "```")

				restart <- true // TODO: why does notification have to come first here...

			// watch for errors
			case err := <-watcher.Errors:
				logger("ERROR", err.Error())
				Printy(err.Error(), 2)
			}
		}
	}()

	if err := watcher.Add(os.Getenv("TLS_KEY")); err != nil {
		logger("ERROR", err.Error())
		Printy(err.Error(), 2)
	}

	<-done
}
