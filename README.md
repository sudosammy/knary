# knary - A simple HTTP(S) and DNS Canary
[![Build Status](https://travis-ci.org/goku-KaioKen/knary.svg?branch=master)](https://travis-ci.org/goku-KaioKen/knary)

>Like "Canary" but more hipster, which means better 😎😎😎

knary is a canary token server that notifies a Slack/Discord/Teams channel (or other webhook) when incoming HTTP(S) or DNS requests match a given domain or any of its subdomains. It also supports functionality useful in offensive engagements including subdomain blacklisting.

![knary canary-ing](https://github.com/sudosammy/knary/raw/master/screenshots/canary.gif "knary canary-ing")

## Why is this useful?

Redteamers use canaries to be notified when someone (or *something*) attempts to interact with a server they control. Canaries help provide visibility over processes that were previously unknown. They can help find areas to probe for RFI or SSRF vulnerabilities, disclose previously unknown servers, provide evidence of a MitM device, or just announce someone interacting with your server.

Defenders also use canaries as tripwires that can alert them of an attacker within their network by having the attacker announce themselves. https://canarytokens.org offers a number of additional ways for defenders to use canaries.

## Setup / Usage

1. Download the [applicable 64-bit knary binary](https://github.com/sudosammy/knary/releases) __OR__ build knary from source:

__Prerequisite:__ You need Go >=1.9 to build knary yourself. Ideally, use Go 1.12.x.
```
go get -u github.com/sudosammy/knary
```
2. Create an `A` record matching a subdomain wildcard (`*.mycanary.com`) to your server's IP address
3. Create an `NS` record matching `dns.mycanary.com` with `ns.mycanary.com` - knary will receive all DNS requests for `*.dns.mycanary.com` 
4. You can self-sign the certificate for accepting TLS connections with something like `openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes`. However, some hosts might refuse to connect - so better you letsencrypt yourself a wildcard cert with something like `sudo certbot certonly --server https://acme-v02.api.letsencrypt.org/directory --manual --preferred-challenges dns -d *.mycanary.com`
5. Setup your [webhook](https://github.com/sudosammy/knary#webhook-config)
6. Create a `.env` file in the same directory as the binary and [configure](https://github.com/sudosammy/knary#config-options) it as necessary. Examples can be found in `examples/`
7. Run the binary (probably in `screen`, `tmux`, or similar because knary can't daemon _yet_) and hope for output that looks something like this: 

![knary go-ing](https://github.com/sudosammy/knary/raw/master/screenshots/run.png "knary go-ing")

## Testing
See & run `test_knary.sh`

## Blacklisting matches
You might find systems that spam your knary even long after an engagement has ended. To stop these from cluttering your Slack channel knary supports a blacklist (location specified in `.env`). Add the offending subdomains or IP addresses separated by a newline:
```
mycanary.com
www.mycanary.com
171.244.140.247
```
This would stop knary from alerting on `www.mycanary.com` but not `another.www.mycanary.com`. Changes to this file will require a knary restart.

## Necessary Config
Example config files can be found in `examples/`
* `DNS` Enable/Disable the DNS canary
* `HTTP` Enable/Disable the HTTP(S) canary
* `BIND_ADDR` The IP address you want knary to listen on. Example input: `0.0.0.0` to bind to all addresses available
* `CANARY_DOMAIN` The domain + TLD to match canary hits on. Example input: `mycanary.com` (knary will match `*.mycanary.com`)
* `TLS_*` (CRT/KEY) The location of your certificate and private key necessary for accepting TLS (https) requests

### Webhook Config
* `SLACK_WEBHOOK` __Optional__ The full URL of the [incoming webhook](https://api.slack.com/custom-integrations/incoming-webhooks) for the Slack channel you want knary to notify
* `DISCORD_WEBHOOK` __Optional__ The full URL of the [Discord webhook](https://discordapp.com/developers/docs/resources/webhook) for the Discord channel you want knary to notify
* `TEAMS_WEBHOOK` __Optional__ The full URL of the [Microsoft Teams webhook](https://docs.microsoft.com/en-us/microsoftteams/platform/concepts/connectors/connectors-using#setting-up-a-custom-incoming-webhook) for the Teams channel you want knary to notify
* `PUSHOVER_TOKEN` __Optional__ The application token for the [Pushover Application](https://pushover.net/) you want knary to notify
* `PUSHOVER_USER` __Optional__ The user token of the Pushover user you want knary to nofify

### Burp Collaborator Config
If you are running Burp Collaborator on the same server as knary, you will need to configure the following.
* `BURP` __Optional__ Enable Burp Collaborator friendly mode
* `BURP_DOMAIN` The domain + TLD to match Collaborator hits on (e.g. `burp.{CANARY_DOMAIN}`). This needs to be an `NS` record much like the knary DNS configuration. See step 3. Example input: `burp.mycanary.com`
* `BURP_DNS_PORT` Local Burp Collaborator DNS port. This can't be 53, because knary listens on that one! Change Collaborator config to be something like 8053, and set this to `8053`
* `BURP_HTTP_PORT` Much like the above - set to `8080` (or whatever you set the Burp HTTP port to be)
* `BURP_HTTPS_PORT` Much like the above - set to `8443` (or whatever you set the Burp HTTPS port to be)
* `BURP_INT_IP` __Optional__ The internal IP address that Burp Collaborator is bound to. In most cases this will be `127.0.0.1` (which is the default); however, if you run knary in Docker you will need to set this to the Burp Collaborator IP address reachable from within the knary container

### Other Config Options
* `DEBUG` __Optional__ Enable/Disable displaying incoming requests in the terminal and some additional info. Default disabled.
* `EXT_IP` __Optional__ The IP address the DNS canary will answer `A` questions with. By default knary will use the answer to `knary.{CANARY_DOMAIN}.`. Setting this option will overrule that behaviour
* `DNS_SERVER` __Optional__ The DNS server to use when asking `dns.{CANARY_DOMAIN}.`. This option is obsolete if `EXT_IP` is set. Default is Google's nameserver: `8.8.8.8`
* `LOG_FILE` __Optional__ Location for a file that knary will log timestamped matches and some errors. Example input: `/home/me/knary.log`
* `BLACKLIST_FILE` __Optional__ Location for a file containing subdomains (separated by newlines) that should be ignored by knary and not logged or posted to Slack. Example input: `blacklist.txt` 
* `BLACKLIST_ALERTING` __Optional__ By default knary will alert on items in the blacklist that haven't triggered in >14 days. Set to `false` to disable this behaviour
