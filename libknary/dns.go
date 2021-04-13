package libknary

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

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

func HandleDNS(w dns.ResponseWriter, r *dns.Msg, EXT_IP string) {
	// many thanks to the original author of this function
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Authoritative = true
	parseDNS(m, w.RemoteAddr().String(), EXT_IP)
	w.WriteMsg(m)
}

func parseDNS(m *dns.Msg, ipaddr string, EXT_IP string) {
	// for each DNS question to our nameserver
	// there can be multiple questions in the question section of a single request
	for _, q := range m.Question {

		switch q.Qtype {
		case dns.TypeA:
			Printy("Got A question", 3)

		case dns.TypeTXT:
			Printy("Got TXT question", 3)

		case dns.TypeSOA:
			Printy("Got SOA question", 3)

			rr, _ := dns.NewRR(fmt.Sprintf("%s IN SOA %s %s (%s)", q.Name, "ns."+os.Getenv("CANARY_DOMAIN"), "admin."+os.Getenv("CANARY_DOMAIN"), "2020080302 7200 3600 604800 300"))
			m.Answer = append(m.Answer, rr)

		case dns.TypeNS:
			Printy("Got NS question", 3)

			rr, _ := dns.NewRR(fmt.Sprintf("%s IN NS %s", q.Name, "ns."+q.Name))
			m.Answer = append(m.Answer, rr)
		}

		// we only care about A questions
		if q.Qtype == dns.TypeA {
			//if we're in burp mode, we don't care about requests to the burp domain (and want to send them to the burp collab listener)
			if os.Getenv("BURP") == "true" {
				if strings.HasSuffix(strings.ToLower(q.Name), strings.ToLower(os.Getenv("BURP_DOMAIN"))+".") {
					// to support our container friends - let the player choose the IP Burp is bound to
					burpIP := ""
					if os.Getenv("BURP_INT_IP") != "" {
						burpIP = os.Getenv("BURP_INT_IP")
					} else {
						burpIP = "127.0.0.1"
					}

					c := dns.Client{}
					newM := dns.Msg{}
					newM.SetQuestion(q.Name, dns.TypeA)
					r, _, err := c.Exchange(&newM, burpIP+":"+os.Getenv("BURP_DNS_PORT"))
					if err != nil {
						Printy(err.Error(), 2)
						continue
					}
					m.Answer = r.Answer
					//don't continue onto any other code paths if it's a collaborator message
					if os.Getenv("DEBUG") == "true" {
						Printy("Sent DNS to Burp: "+burpIP+":"+os.Getenv("BURP_DNS_PORT"), 3)
					}
					continue
				}
			}

			/*
			As of version 3.2.0 we are always the authorative nameserver for our knary.
			Therefore, at this part of the code, all *.knary.tld "A" questions are here.
			To avoid changing the way knary alerts webhooks <2.4.0 we will respond with our IP address.
			This results in a wildcard DNS record for *.knary.tld but to only alert on *.dns.knary.tld.
			*/
			if !strings.HasSuffix(strings.ToLower(q.Name), strings.ToLower(".dns."+os.Getenv("CANARY_DOMAIN")+".")) {
				rr, _ := dns.NewRR(fmt.Sprintf("%s IN 60 A %s", q.Name, EXT_IP))
				m.Answer = append(m.Answer, rr)
				return
			}

			if os.Getenv("DEBUG") == "true" {
				Printy("DNS question for: "+q.Name, 3)
			}

			if !inBlacklist(q.Name, ipaddr) {
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
					logger("INFO", ipaddr+" - "+q.Name)

				} else {
					go sendMsg("DNS: " + q.Name +
						"```" +
						"From: " + ipaddr + "\n" +
						"PTR: " + reverse +
						"```")
					logger("INFO", ipaddr+" - "+reverse+" - "+q.Name)
				}
			}

			if os.Getenv("DEBUG") == "true" {
				Printy("Responding with: "+EXT_IP, 3)
			}

			rr, _ := dns.NewRR(fmt.Sprintf("%s IN 60 A %s", q.Name, EXT_IP))
			m.Answer = append(m.Answer, rr)
		}

		// catch TXT lookups because this might be certbot
		if q.Qtype == dns.TypeTXT {
			if os.Getenv("DEBUG") == "true" {
				Printy("TXT DNS question for: "+q.Name, 3)
			}

			// search our zone file for a response
			zoneResponse := inZone(q.Name[:len(q.Name)-1])

			if (zoneResponse != "") {
				// respond
				rr, _ := dns.NewRR(fmt.Sprintf("%s", zoneResponse))
				m.Answer = append(m.Answer, rr)

			} else {
				if os.Getenv("DEBUG") == "true" {
					Printy("No response for that TXT question", 3)
				}
			}
			// assuming it was certbot
			//logger("INFO", "A TXT request was made a for: "+q.Name+". We responded with: "+m.Answer)
		}
	}
}

func PerformALookup(domain string) (string, error) {
	// perform an A lookup on the canary domain and use that for our reply
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
