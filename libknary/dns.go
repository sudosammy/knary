package libknary

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// AcceptDNS allows is to accept DNS connections for knary
func AcceptDNS(wg *sync.WaitGroup) {
	// start DNS server
	server := &dns.Server{Addr: os.Getenv("BIND_ADDR") + ":53", Net: "udp"}
	err := server.ListenAndServe()

	if err != nil {
		GiveHead(2)
		log.Fatal(err)
	}

	defer server.Shutdown()
	wg.Done()
}

// DNS is specified in RFC 1034 / RFC 1035
// +---------------------+
// |        Header       |
// +---------------------+
// |       Question      | the question for the name server
// +---------------------+
// |        Answer       | RRs answering the question
// +---------------------+
// |      Authority      | RRs pointing toward an authority
// +---------------------+
// |      Additional     | RRs holding additional information
// +---------------------+
//
//  DNS Header
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      ID                       |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    QDCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ANCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    NSCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ARCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// HandleDNS is used to handle DNS replies
func HandleDNS(w dns.ResponseWriter, r *dns.Msg, ExtIP string) {
	// many thanks to the original author of this function
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Authoritative = true
	parseDNS(m, w.RemoteAddr().String(), ExtIP)
	w.WriteMsg(m)
}

func parseDNS(m *dns.Msg, ipaddr string, ExtIP string) {
	// for each DNS question to our nameserver
	// there can be multiple questions in the question section of a single request
	for _, q := range m.Question {
		// we only care about A questions
		if q.Qtype == dns.TypeA {
			if os.Getenv("DEBUG") == "true" {
				Printy("DNS question for: "+q.Name, 3)
			}

			if !inBlacklist(q.Name) {
				// spit the IP address to remove the port
				// be wary of IPv6
				ipSlice := strings.Split(ipaddr, ":")
				ipSlice = ipSlice[:len(ipSlice)-1]
				ipaddrNoPort := strings.Join(ipSlice[:], ",")

				reverse, _ := dns.ReverseAddr(ipaddrNoPort)

				if reverse == "" {
					go sendMsg("DNS: " + q.Name +
						"```" +
						"From: " + ipaddr +
						"```")
					logger("[" + ipaddr + "]\n" + q.Name)

				} else {
					go sendMsg("DNS: " + q.Name +
						"```" +
						"From: " + ipaddr + "\n" +
						"PTR: " + reverse +
						"```")
					logger("[" + ipaddr + "]\n" + "[" + reverse + "]\n" + q.Name)
				}
			}

			// if ExtIP is set, it overrules the A lookup
			if os.Getenv("ExtIP") == "" {
				if os.Getenv("DEBUG") == "true" {
					Printy("Responding with: "+ExtIP, 3)
				}

				rr, _ := dns.NewRR(fmt.Sprintf("%s IN 60 A %s", q.Name, ExtIP))
				m.Answer = append(m.Answer, rr)

			} else {
				if os.Getenv("DEBUG") == "true" {
					Printy("Responding with: "+os.Getenv("ExtIP"), 3)
				}

				rr, _ := dns.NewRR(fmt.Sprintf("%s IN 60 A %s", q.Name, os.Getenv("ExtIP")))
				m.Answer = append(m.Answer, rr)
			}
		}
	}
}

// PerformALookup performs an A lookup on the canary domain and use that for our reply
func PerformALookup(domain string) (string, error) {
	kMsg := new(dns.Msg)
	kMsg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// query dns server for dns.mycanary.com.
	var nameServ string
	if os.Getenv("DNS_SERVER") == "" {
		nameServ = "8.8.8.8"
	} else {
		nameServ = os.Getenv("DNS_SERVER")
	}

	answ, _, err := new(dns.Client).Exchange(kMsg, nameServ+":53")

	if err != nil {
		return "", err
	}

	if len(answ.Answer) == 0 {
		return "", nil
	}

	// https://stackoverflow.com/questions/38625233/what-does-key-ok-k-dns-a-mean-in-go
	if t, ok := answ.Answer[0].(*dns.A); ok {
		if os.Getenv("DEBUG") == "true" {
			Printy("Answering DNS requests with: "+t.A.String(), 3)
		}
		return t.A.String(), nil
	}

	return "", nil
}
