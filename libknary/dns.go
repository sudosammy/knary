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

func infoLog(ipaddr string, reverse string, name string) {
	// only log informationals if DEBUG is true
	if os.Getenv("DEBUG") == "true" {
		logger("INFO", ipaddr+" - "+reverse+" - "+name)
	}
}

func goSendMsg(ipaddr, reverse, name, record string) bool {
	if os.Getenv("DNS_SUBDOMAIN") != "" &&
		!stringContains(name, os.Getenv("DNS_SUBDOMAIN")+"."+os.Getenv("CANARY_DOMAIN")) {
		// disregard unless subdomain we want to report on
		return false
	}

	if os.Getenv("DEBUG") == "true" {
		Printy("Got A question for: " + name, 3)
	}

	if inBlacklist(name, ipaddr) {
		return false
	}

	if reverse == "" {
		go sendMsg("DNS (" + record + "): " + name +
			"```" +
			"From: " + ipaddr +
			"```")
		infoLog(ipaddr, reverse, name)

	} else {
		go sendMsg("DNS (" + record + "): " + name +
			"```" +
			"From: " + ipaddr + "\n" +
			"PTR: " + reverse +
			"```")
		infoLog(ipaddr, reverse, name)
	}
	return true
}

func parseDNS(m *dns.Msg, ipaddr string, EXT_IP string) {
	// for each DNS question to our nameserver
	// there can be multiple questions in the question section of a single request
	for _, q := range m.Question {
		// search zone file and append response if found
		zoneResponse, foundInZone := inZone(q.Name, q.Qtype)
		if foundInZone {
			m.Answer = append(m.Answer, zoneResponse)
		}

		// catch requests to pass through to burp
		if os.Getenv("BURP_DOMAIN") != "" {
			if strings.HasSuffix(strings.ToLower(q.Name), strings.ToLower(os.Getenv("BURP_DOMAIN"))+".") {
				// to support our container friends - let the player choose the IP Burp is bound to
				burpIP := ""
				if os.Getenv("BURP_INT_IP") != "" {
					burpIP = os.Getenv("BURP_INT_IP")
				} else {
					burpIP = "127.0.0.1"
				}

				// https://github.com/sudosammy/knary/issues/43
				//ipaddrNoPort, port := splitPort(ipaddr)
				// c := new(dns.Client)
				// laddr := net.UDPAddr{
				// 	IP:   net.ParseIP(ipaddrNoPort),
				// 	Port: port,
				// 	Zone: "",
				// }
				// c.Dialer = &net.Dialer{
				// 	//Timeout: 200 * time.Millisecond,
				// 	LocalAddr: &laddr,
				// }

				c := dns.Client{}
				newM := dns.Msg{}
				newM.SetQuestion(q.Name, dns.TypeA)
				r, _, err := c.Exchange(&newM, burpIP+":"+os.Getenv("BURP_DNS_PORT"))

				if err != nil {
					Printy(err.Error(), 2)
					return
				}
				m.Answer = r.Answer
				// don't continue onto any other code paths if it's a collaborator message
				if os.Getenv("DEBUG") == "true" {
					Printy("Sent question "+q.Name+" to Collaborator: "+burpIP+":"+os.Getenv("BURP_DNS_PORT"), 3)
				}
				return
			}
		}

		switch q.Qtype {
		case dns.TypeA:
			ipaddrNoPort, _ := splitPort(ipaddr)
			reverse, _ := dns.ReverseAddr(ipaddrNoPort)
			goSendMsg(ipaddr, reverse, q.Name, "A")
			/*
				If we are an IPv6 host, to be a "compliant" nameserver (https://tools.ietf.org/html/rfc4074), we should:
				a) Return an empty response to A questions
				b) Return our SOA in the AUTHORITY section
				Let me know if you can do "b"
			*/
			if IsIPv6(EXT_IP) {
				return
			}
			if !foundInZone {
				rr, _ := dns.NewRR(fmt.Sprintf("%s IN 60 A %s", q.Name, EXT_IP))
				m.Answer = append(m.Answer, rr)
			}

		case dns.TypeAAAA:
			ipaddrNoPort, _ := splitPort(ipaddr)
			reverse, _ := dns.ReverseAddr(ipaddrNoPort)
			goSendMsg(ipaddr, reverse, q.Name, "AAAA")
			/*
				If we are an IPv4 host, to be a "compliant" nameserver (https://tools.ietf.org/html/rfc4074), we should:
				a) Return an empty response to AAAA questions
				b) Return our SOA in the AUTHORITY section
				Let me know if you can do "b"
			*/
			if IsIPv4(EXT_IP) {
				return
			}
			if !foundInZone {
				rr, _ := dns.NewRR(fmt.Sprintf("%s IN 60 AAAA %s", q.Name, EXT_IP))
				m.Answer = append(m.Answer, rr)
			}

		case dns.TypeCNAME:
			if strings.HasPrefix(strings.ToLower(q.Name), strings.ToLower(os.Getenv("CANARY_DOMAIN")+".")) {
				// CNAME records cannot be returned for the root domain anyway.
				return
			}

			ipaddrNoPort, _ := splitPort(ipaddr)
			reverse, _ := dns.ReverseAddr(ipaddrNoPort)
			goSendMsg(ipaddr, reverse, q.Name, "CNAME")

			if !foundInZone {
				rr, _ := dns.NewRR(fmt.Sprintf("%s IN 60 CNAME %s", q.Name, q.Name))
				m.Answer = append(m.Answer, rr)
			}

		case dns.TypeTXT:
			ipaddrNoPort, _ := splitPort(ipaddr)
			reverse, _ := dns.ReverseAddr(ipaddrNoPort)
			goSendMsg(ipaddr, reverse, q.Name, "TXT")

			if !foundInZone {
				return
			}

		// for other nameserver functions
		case dns.TypeSOA:
			if os.Getenv("DEBUG") == "true" {
				Printy("Got SOA question for: "+q.Name, 3)
			}

			if !foundInZone {
				rr, _ := dns.NewRR(fmt.Sprintf("%s IN SOA %s %s (%s)", os.Getenv("CANARY_DOMAIN"), "ns."+os.Getenv("CANARY_DOMAIN"), "admin."+os.Getenv("CANARY_DOMAIN"), "2021041401 7200 3600 604800 300"))
				m.Answer = append(m.Answer, rr)
			}

		case dns.TypeNS:
			if os.Getenv("DEBUG") == "true" {
				Printy("Got NS question for: "+q.Name, 3)
			}

			if !foundInZone {
				rr, _ := dns.NewRR(fmt.Sprintf("%s IN NS %s", q.Name, "ns."+os.Getenv("CANARY_DOMAIN")))
				m.Answer = append(m.Answer, rr)
			}
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
			if IsIP(t.A.String()) {
				return t.A.String(), nil
			} else {
				return "", errors.New("Malformed response from A question")
			}
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
		if IsIP(t.A.String()) {
			return t.A.String(), nil
		} else {
			return "", errors.New("Couldn't get glue record for " + os.Getenv("CANARY_DOMAIN") + ". Have you configured a glue record for your domain? Has it propagated? You can set EXT_IP to bypass this but... do you know what you're doing?")
		}
	}

	return "", errors.New("Couldn't find glue record for " + os.Getenv("CANARY_DOMAIN") + ". You can set EXT_IP to bypass this but... do you know what you're doing?")
}
