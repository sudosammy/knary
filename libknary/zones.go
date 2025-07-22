package libknary

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

/*
LoadZone: Parse zone file and add to map
inZone: Take a question name and type and return dns.RR response + bool if found
*/
var zoneMap = map[string]map[int]dns.RR{}
var fqdnCounter = map[string]int{}
var zoneCounter = 0

func LoadZone() (bool, error) {
	// Check if ZONE_FILE environment variable is set
	zoneFile := os.Getenv("ZONE_FILE")
	if zoneFile == "" {
		return true, nil
	}

	if _, err := os.Stat(zoneFile); os.IsNotExist(err) {
		return false, err
	}

	zlist, err := os.Open(zoneFile)
	if err != nil {
		Printy(err.Error()+" - ignoring", 3)
		return false, err
	}
	defer zlist.Close()

	// https://pkg.go.dev/github.com/miekg/dns#ZoneParser
	zp := dns.NewZoneParser(bufio.NewReader(zlist), "", "")

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if zoneMap[rr.Header().Name] == nil {
			zoneMap[rr.Header().Name] = map[int]dns.RR{}
		}
		zoneMap[rr.Header().Name][fqdnCounter[rr.Header().Name]] = rr
		fqdnCounter[rr.Header().Name]++
		zoneCounter++
	}

	if err := zp.Err(); err != nil {
		logger("ERROR", err.Error())
		return false, err
	}

	Printy("Monitoring "+strconv.Itoa(zoneCounter)+" items in zone", 1)
	logger("INFO", "Monitoring "+strconv.Itoa(zoneCounter)+" items in zone")
	return true, nil
}

func inZone(needle string, qType uint16) (map[int]dns.RR, bool) {
	// if last character of needle isn't a period, add it
	if needle[len(needle)-1] != '.' {
		needle += "."
	}

	if val, ok := zoneMap[strings.ToLower(needle)]; ok {
		// this (sub)domain is present in the zone file
		// confirm whether one or many match the qType
		var appendKey int
		returnMap := make(map[int]dns.RR)
		for k := range zoneMap[strings.ToLower(needle)] {
			if val[k].Header().Rrtype == qType {
				returnMap[appendKey] = val[k]
				appendKey++
			}
		}
		// catch if there were no matching qTypes
		if len(returnMap) == 0 {
			return nil, false
		}

		if os.Getenv("DEBUG") == "true" {
			Printy(needle+" found in zone file. Responding with "+strconv.Itoa(len(returnMap))+" response(s)", 3)
		}
		return returnMap, true
	}
	return nil, false
}

func addZone(fqdn string, ttl int, qType string, value string) error {
	rr, err := dns.NewRR(fmt.Sprintf("%s IN %d %s %s", strings.ToLower(fqdn), ttl, qType, value))

	if err != nil {
		Printy(err.Error(), 3)
		return err
	}

	nextVal := len(zoneMap[rr.Header().Name])
	if zoneMap[rr.Header().Name] == nil {
		zoneMap[rr.Header().Name] = map[int]dns.RR{}
	}
	zoneMap[rr.Header().Name][nextVal] = rr

	if os.Getenv("DEBUG") == "true" {
		Printy(fqdn+" "+qType+" added to zone with ID: "+strconv.Itoa(nextVal), 3)
	}
	return nil
}

func remZone(fqdn string) {
	// if last character of fqdn isn't a period, add it
	if fqdn[len(fqdn)-1] != '.' {
		fqdn += "."
	}

	// this is pretty dodgy.
	// we're hoping that the last zone added to the map is the one we want to delete
	lastVal := len(zoneMap[fqdn]) - 1
	_, ok := zoneMap[fqdn][lastVal]
	if ok {
		delete(zoneMap[fqdn], lastVal)
		if os.Getenv("DEBUG") == "true" {
			Printy("Deleted "+fqdn+" with ID: "+strconv.Itoa(lastVal)+" from zone", 3)
		}
	}
}
