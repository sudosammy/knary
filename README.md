# knary - A simple HTTP(S) and DNS Canary Slackbot

>Like "Canary" but more hipster, which means better 😎😎😎

knary is a canary token server that notifies a Slack channel when incoming HTTP(S) or DNS requests match a given domain or any of its subdomains. It also supports functionality useful in offensive engagements including subdomain blacklisting.

![knary canary-ing](https://github.com/sudosammy/knary/raw/master/screenshots/canary.gif "knary canary-ing")

## Why is this useful?

Redteamers use canaries to be notified when someone (or *something*) attempts to interact with a server they control. Canaries help provide visibility over processes that were previously unknown. They can help find areas to probe for RFI or SSRF vulnerabilities, disclose previously unknown servers, provide evidence of a MitM device, or just announce someone interacting with your server.

Defenders also use canaries as tripwires that can alert them of an attacker within their network by having the attacker announce themselves. https://canarytokens.org offers a number of additional ways for defenders to use canaries.

### Why actually?

Because I wanted a project to help me learn Golang.

## Setup / Usage

1. Download the [applicable 64-bit knary binary](https://github.com/sudosammy/knary/releases) __OR__ build knary from source:

__Prerequisite:__ You need Go >=1.9 to build knary yourself. Ideally, use Go 1.10.x.
```
go get -u github.com/sudosammy/knary
```
2. Create an `A` record matching a subdomain wildcard (`*.mycanary.com`) to your server's IP address
3. Create an `NS` record matching `dns.mycanary.com` with `ns.mycanary.com` - knary will receive all DNS requests for `*.dns.mycanary.com` 
4. You can self-sign the certificate for accepting TLS connections with something like `openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes`. However, some hosts might refuse to connect - so better you letsencrypt yourself a wildcard cert with something like `sudo certbot certonly --server https://acme-v02.api.letsencrypt.org/directory --manual --preferred-challenges dns -d *.mycanary.com`
5. Setup your [slack webhook](https://slack.com/apps/A0F7XDUAZ-incoming-webhooks)
6. Create a `.env` file in the same directory as the binary and [configure](https://github.com/sudosammy/knary#config-options) it as necessary:

```
DNS=true
HTTP=true
BIND_ADDR=0.0.0.0
CANARY_DOMAIN=mycanary.com
TLS_CRT=path/to/certificate.crt
TLS_KEY=path/to/private.key

DEBUG=false
LOG_FILE=knary.log
BLACKLIST_FILE=blacklist.txt

SLACK_WEBHOOK=https://hooks.slack.com/services/...
```
7. Run the binary (probably in `screen`, `tmux`, or similar because knary can't daemon _yet_) and hope for output that looks something like this: 

![knary go-ing](https://github.com/sudosammy/knary/raw/master/screenshots/run.png "knary go-ing")

## Testing
* HTTP(S) - `curl http://test.mycanary.com` & `curl https://test.mycanary.com`
* DNS - `dig test.dns.mycanary.com`

## Blacklisting matches
You might find systems that spam your knary even long after an engagement has ended. To stop these from cluttering your Slack channel knary supports a blacklist (location specified in `.env`). Add the offending subdomains separated by a newline:
```
www.mycanary.com
dns.mycanary.com
```
This would stop knary from alerting on `www.mycanary.com` but not `another.www.mycanary.com`. Changes to this file will come into effect immediately without requiring a knary restart.

## Config Options
* `DNS` Enable/Disable the DNS canary
* `HTTP` Enable/Disable the HTTP(S) canary
* `BIND_ADDR` The IP address you want knary to listen on. Example input: `0.0.0.0` to bind to all addresses available
* `CANARY_DOMAIN` The domain + TLD to match canary hits on. Example input: `mycanary.com` (knary will match `*.mycanary.com`)
* `TLS_*` The location of your certificate and private key necessary for accepting TLS (https) requests
* `DEBUG` Enable/Disable displaying incoming requests in the terminal and some additional info
* `SLACK_WEBHOOK` The full URL of the [incoming webhook](https://api.slack.com/custom-integrations/incoming-webhooks) for the Slack channel you want knary to notify
* `EXT_IP` __Optional__ The IP address the DNS canary will answer `A` questions with. By default knary will use the answer to `knary.{CANARY_DOMAIN}.`. Setting this option will overrule that behaviour
* `DNS_SERVER` __Optional__ The DNS server to use when asking `dns.{CANARY_DOMAIN}.`. This option is obsolete if `EXT_IP` is set. Default is Google's nameserver: `8.8.8.8`
* `LOG_FILE` __Optional__ Location for a file that knary will log timestamped matches and some errors. Example input: `/home/me/knary.log`
* `BLACKLIST_FILE` __Optional__ Location for a file containing subdomains (separated by newlines) that should be ignored by knary and not logged or posted to Slack. Example input: `blacklist.txt` 
* `TIMEOUT` __Optional__ The timeout for reading the HTTP(S) request. Default is 2 seconds. Example input: `1`
