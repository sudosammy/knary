# knary - A simple HTTP(S) and DNS Canary

[![Build Status](https://travis-ci.org/sudosammy/knary.svg?branch=master)](https://travis-ci.org/sudosammy/knary)  [![Coverage Status](https://coveralls.io/repos/github/sudosammy/knary/badge.svg?branch=master)](https://coveralls.io/github/sudosammy/knary?branch=master)

⚠️ **Note: Upgrading from version 2? You need to change your DNS setup. See step #2 and #3 below.** ⚠️

>Like "Canary" but more hipster, which means better 😎😎😎

knary is a canary token server that notifies a Slack/Discord/Teams/Lark channel (or other webhook) when incoming HTTP(S) or DNS requests match a given domain or any of its subdomains. It also supports functionality useful in offensive engagements including subdomain denylisting, working with Burp Collaborator, and running from a container.

![knary canary-ing](https://github.com/sudosammy/knary/raw/master/screenshots/canary.gif "knary canary-ing")

## Why is this useful?

Redteamers use canaries to be notified when someone (or *something*) attempts to interact with a server they control. Canaries help provide visibility over processes that were previously unknown. They can help find areas to probe for RFI or SSRF vulnerabilities, disclose previously unknown servers, provide evidence of a MitM device, or just announce someone interacting with your server.

Defenders also use canaries as tripwires that can alert them of an attacker within their network by having the attacker announce themselves. https://canarytokens.org offers a number of additional ways for defenders to use canaries.

## Setup / Usage

1. Download the [applicable 64-bit knary binary](https://github.com/sudosammy/knary/releases) __OR__ build knary from source:

__Prerequisite:__ You need Go >=1.13 to build knary. Ideally, use Go 1.16.x.
```
go get -u github.com/sudosammy/knary
```

2. Update your domain nameserver(s) to point to a subdomain under itself; such as `ns.knary.tld`. If required, you can set multiple nameserver records such as `ns1.knary.tld`, `ns2.knary.ltd`.

3. Create a "Glue Record", sometimes referred to as the "Nameserver Registration", or "Nameserver IP address" to point to your knary server. This is what it looks like in `name.com`:

 ![Setting a glue record](https://github.com/sudosammy/knary/raw/master/screenshots/nameserver-ip.png "Setting a glue record")

**Note:** You may need to raise a support ticket to have step #2 and #3 performed by your registrar. If your registry requires you to have multiple nameservers but doesn't permit them to use the same IP address for both, set the second one to other nameserver, such as `8.8.8.8` or `1.1.1.1`.

4. This will take some time to propagate, so setup your [webhook](https://github.com/sudosammy/knary#webhook-config).

5. Create a `.env` file in the same directory as the knary binary and [configure](https://github.com/sudosammy/knary#config-options) it as necessary. Examples can be found in `examples/`. You can also use environment variables to set these configurations.

6. __Optional__ For accepting TLS (HTTPS) connections you can create a self-signed certificate; however, some hosts might refuse to connect to you. It's better if you letsencrypt yourself a wildcard cert with something like `sudo certbot certonly --server https://acme-v02.api.letsencrypt.org/directory --manual --preferred-challenges dns -d *.knary.tld`

7. __Optional__ When doing this `certbot` will ask you to set a TXT DNS record. You can do this by setting the `ZONE_FILE` configuration option with knary. You can use the example found in `examples/zone_file.txt` to set the DNS response required. Complete the next step before hitting "Enter" in `certbot`.

8. Run the binary (probably in `screen`, `tmux`, or similar) and hope for output that looks something like this (`DEBUG` is on): 

![knary go-ing](https://github.com/sudosammy/knary/raw/master/screenshots/run.png "knary go-ing")

## Denying matches
You might find systems that spam your knary even long after an engagement has ended. To stop these from cluttering your notifications knary supports a denylist (location specified in `.env`). Add the offending subdomains or IP addresses separated by a newline:
```
knary.tld
www.knary.tld
171.244.140.247
```
This would stop knary from alerting on `www.knary.tld` but not `another.www.knary.tld`. Changes to this file will require a knary restart. A sample can be found in `examples/denylist.txt` with common subdomains to include.

**Important:** You will almost certainly want to include your TLD, `ns`, and `_acme-challenge` subdomains (e.g. `mycanary.com`, `ns.mycanary.com`, and `_acme-challenge.mycanary.com`) as several mundane systems will perform DNS lookups against these records every day.

## Necessary Config
Example config can be found in `examples/`
* `DNS` Enable/Disable the DNS canary
* `HTTP` Enable/Disable the HTTP canary
* `BIND_ADDR` The IP address you want knary to listen on. Example: `0.0.0.0` to bind to all addresses available
* `CANARY_DOMAIN` The domain + TLD to match canary hits on. Example input: `knary.tld` (knary will match `*.knary.tld`)
* `TLS_*` (CRT/KEY) The location of your certificate and private key necessary for accepting TLS (HTTPS) requests

### Webhook Config
* `SLACK_WEBHOOK` __Optional__ The full URL of the [incoming webhook](https://api.slack.com/custom-integrations/incoming-webhooks) for the Slack channel you want knary to notify
* `DISCORD_WEBHOOK` __Optional__ The full URL of the [Discord webhook](https://discordapp.com/developers/docs/resources/webhook) for the Discord channel you want knary to notify
* `TEAMS_WEBHOOK` __Optional__ The full URL of the [Microsoft Teams webhook](https://docs.microsoft.com/en-us/microsoftteams/platform/concepts/connectors/connectors-using#setting-up-a-custom-incoming-webhook) for the Teams channel you want knary to notify
* `PUSHOVER_TOKEN` __Optional__ The application token for the [Pushover Application](https://pushover.net/) you want knary to notify
* `PUSHOVER_USER` __Optional__ The user token of the Pushover user you want knary to nofify
* `LARK_WEBHOOK` __Optional__ The full URL of the [webhook](https://www.feishu.cn/hc/en-US/articles/360024984973-Bot-Use-bots-in-groups) for the Lark/Feishu bot you want knary to notify
* `LARK_SECRET` __Optional__ The [secret token](https://www.feishu.cn/hc/en-US/articles/360024984973-Bot-Use-bots-in-groups) used to sign messages to your Lark/Feishu bot

### Burp Collaborator Config
**Note:** If you have previously been running knary with Let's Encrypt and have now configured Burp Collaborator, you will need to delete the certificates in the `certs/` folder so that knary can re-generate certificates that include your Burp Collaborator subdomain.

If you are running Burp Collaborator on the same server as knary, you will need to configure the following.
* `BURP_DOMAIN` The domain + TLD to match Collaborator hits on (e.g. `burp.{CANARY_DOMAIN}`).
* `BURP_DNS_PORT` Local Burp Collaborator DNS port. This can't be 53, because knary listens on that one! Change Collaborator config to be something like 8053, and set this to `8053`
* `BURP_HTTP_PORT` Much like the above - set to `8080` (or whatever you set the Burp HTTP port to be)
* `BURP_HTTPS_PORT` Much like the above - set to `8443` (or whatever you set the Burp HTTPS port to be)
* `BURP_INT_IP` __Optional__ The internal IP address that Burp Collaborator is bound to. In most cases this will be `127.0.0.1` (which is the default); however, if you run knary in Docker you will need to set this to the Burp Collaborator IP address reachable from within the knary container

### Optional Config Options
* `DEBUG` __Optional__ Enable/Disable displaying incoming requests in the terminal and some additional info. Default disabled.
* `EXT_IP` __Optional__ The IP address the DNS canary will answer `A` questions with. By default knary will use the nameserver glue record. Setting this option will overrule that behaviour
* `LOG_FILE` __Optional__ Location for a file that knary will log timestamped matches and some errors. Example input: `/home/me/knary.log`
* `DENYLIST_FILE` __Optional__ Location for a file containing case-insensitive subdomains (separated by newlines) that should be ignored by knary and not logged or posted to Slack. Example input: `denylist.txt` 
* `DENYLIST_ALERTING` __Optional__ By default knary will alert on items in the denylist that haven't triggered in >14 days. Set to `false` to disable this behaviour
* `ZONE_FILE` __Optional__ knary supports responding to requests based on an RFC 1034/1035 compliant zone file. Example input: `zone.txt`
