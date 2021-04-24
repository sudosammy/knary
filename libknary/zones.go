package libknary

import (
	"bufio"
	"log"
	"os"
	"strconv"

	"github.com/miekg/dns"
)

/*
	LoadZone: Parse zone file and add to map
	inZone: Take a question name and type and return dns.RR response + bool if found
*/
var zoneMap = map[string]dns.RR{}
var zoneCounter = 0

func LoadZone() (bool, error) {
	if _, err := os.Stat(os.Getenv("ZONE_FILE")); os.IsNotExist(err) {
		return false, err
	}

	zlist, err := os.Open(os.Getenv("ZONE_FILE"))
	defer zlist.Close()

	if err != nil {
		Printy(err.Error()+" - ignoring", 3)
		return false, err
	}

	// https://pkg.go.dev/github.com/miekg/dns#ZoneParser
	zp := dns.NewZoneParser(bufio.NewReader(zlist), "", "")

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		zoneMap[rr.Header().Name] = rr
		zoneCounter++
	}

	if err := zp.Err(); err != nil {
		if err != nil {
			GiveHead(2)
			log.Fatal(err)
		}
	}

	Printy("Monitoring "+strconv.Itoa(zoneCounter)+" items in zone", 1)
	logger("INFO", "Monitoring "+strconv.Itoa(zoneCounter)+" items in zone")
	return true, nil
}

func inZone(needle string, qType uint16) (dns.RR, bool) {
	if val, ok := zoneMap[needle]; (ok && val.Header().Rrtype == qType) {
		if os.Getenv("DEBUG") == "true" {
			Printy(needle+" found in zone file", 3)
		}
		return val, true
	}
	return nil, false
}
