package libknary

import (
	"errors"
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

			rr, _ := dns.NewRR(fmt.Sprintf("%s IN SOA %s %s (%s)", os.Getenv("CANARY_DOMAIN"), "ns."+os.Getenv("CANARY_DOMAIN"), "admin."+os.Getenv("CANARY_DOMAIN"), "2020080302 7200 3600 604800 300"))
			m.Answer = append(m.Answer, rr)

		case dns.TypeNS:
			Printy("Got NS question", 3)

			rr, _ := dns.NewRR(fmt.Sprintf("%s IN NS %s", q.Name, "ns."+os.Getenv("CANARY_DOMAIN")))
			m.Answer = append(m.Answer, rr)
		}

		/*
			This code changed dramatically in 3.3.0 when we scraped Burp Collab support:
			a) Burp collab is a shitty java app which frequently crashes and we gave up trying to support it,
			b) knary's new nameserver design would have required changes to the code in these functions,
			c) It wasn't a widely used feature for now. knary will probably support it again in the future.
		*/

		// we only care about A questions
		if q.Qtype == dns.TypeA {
			/*
				As of version 3.3.0 we are the authorative nameserver for our knary.
				Therefore, at this part of the code, all *.knary.tld "A" questions are here.
				To avoid changing the way knary alerts webhooks <3.2.0 we will respond with our IP address.
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

			if zoneResponse != "" {
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

func queryDNS(domain string, reqtype string, ns string) (string, error) {
	// Only supports A and NS records for now
	kMsg := new(dns.Msg)

	switch reqtype {
	case "A":
		kMsg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	case "NS":
		kMsg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	}

	answ, _, err := new(dns.Client).Exchange(kMsg, ns+":53")

	if err != nil {
		return "", err
	}

	switch reqtype {
	case "A":
		if len(answ.Answer) == 0 {
			return "", errors.New("No response for A query: " + domain)
		}

		if t, ok := answ.Answer[0].(*dns.A); ok {
			return t.A.String(), nil
		}

	case "NS":
		if len(answ.Ns) == 0 {
			return "", errors.New("No response for NS query: " + domain)
		}

		if t, ok := answ.Ns[0].(*dns.NS); ok {
			return t.Ns, nil
		}
	}

	return "", errors.New("Not an A or NS lookup")
}

func GuessIP(domain string) (string, error) {
	// query a root name server for the nameserver for our tld
	tldDNS, err := queryDNS(domain, "NS", "198.41.0.4")

	if err != nil {
		return "", err
	}

	// query the tld's nameserver for our knary domain and extract the glue record from additional information
	kMsg := new(dns.Msg)
	kMsg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	answ, _, err := new(dns.Client).Exchange(kMsg, tldDNS+":53")

	if len(answ.Extra) == 0 {
		return "", errors.New("No 'Additional' section in NS lookup for: " + domain + " with nameserver: " + tldDNS + " Have you configured a glue record for your domain? Has it propagated? You can set EXT_IP to bypass this but... do you know what you're doing?")
	}

	if t, ok := answ.Extra[0].(*dns.A); ok {
		return t.A.String(), nil
	}

	return "", errors.New("Couldn't find glue record for " + os.Getenv("CANARY_DOMAIN") + ". You can set EXT_IP to bypass this but... do you know what you're doing?")
}
