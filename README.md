# knary - A simple HTTP(S) and DNS Canary

[![Build Status](https://circleci.com/gh/sudosammy/knary/tree/master.svg?style=svg)](https://circleci.com/gh/sudosammy/knary/tree/master)  [![Go Report Card](https://goreportcard.com/badge/github.com/sudosammy/knary/v3)](https://goreportcard.com/report/github.com/sudosammy/knary/v3)  [![Coverage Status](https://coveralls.io/repos/github/sudosammy/knary/badge.svg?branch=master)](https://coveralls.io/github/sudosammy/knary?branch=master)

>Like "Canary" but more hipster, which means better 😎😎😎

knary is a canary token server that notifies a Slack/Discord/Teams/Lark/Telegram channel (or other webhook) when incoming HTTP(S) or DNS requests match a given domain or any of its subdomains. It also supports functionality useful in offensive engagements including subdomain allow/denylisting, working with Burp Collaborator, and automatic TLS certificate management with Let's Encrypt.

![knary canary-ing](https://github.com/sudosammy/knary/raw/master/screenshots/canary.gif "knary canary-ing")

## Why is this useful?

Offensive security teams use canaries to be notified when someone (or *something*) attempts to interact with a server they control. Canaries help provide visibility over processes that were previously unknown. They can help find areas to probe for RFI or SSRF vulnerabilities, disclose previously unknown servers, provide evidence of an intercepting device, or announce someone interacting with your server.

Defenders also use canaries as tripwires that can alert them of an attacker within their network by having the attacker announce themselves. If you are a defender, https://canarytokens.org might be what you’re looking for.

## Setup

1. Download the [applicable 64-bit knary binary](https://github.com/sudosammy/knary/releases) __OR__ build knary from source:

__Prerequisite:__ You need Go >=1.18 to build knary.
```
go install github.com/sudosammy/knary/v3@latest
```

See [here](#inbound-firewall-requirements) for guidance on which ports to open for knary.

**Important:** The specifics of how to perform the next two steps will depend on your domain registrar. Google `How to set Glue Record on <registrar name>` to get started. Ultimately, you need to configure your knary domain(s) to make use of itself as the nameserver (i.e. `ns1.knary.tld` and `ns2.knary.tld`) and configure a Glue Record to point these nameservers back to your knary host IP address. You may need to raise a support ticket to have this performed by your registrar. 

2. Set your chosen knary domain(s) nameserver(s) to point to a subdomain under itself; such as `ns.knary.tld`. If required, set multiple nameserver records such as `ns1` and `ns2`.

3. Create a "Glue Record" (sometimes referred to as "Nameserver Registration" or "Nameserver IP address") to point to your knary server. This is what it looks like in `name.com`:

 ![Setting a glue record](https://github.com/sudosammy/knary/raw/master/screenshots/nameserver-ip.png "Setting a glue record")

If your registry requires you to have multiple nameservers with **different** IP addresses, set the second nameserver to an IP address such as `8.8.8.8` or `1.1.1.1`. 

4. This **will** take time to propagate (often several hours), so go setup your [webhook(s)](#supported-webhook-configurations) while you wait. You can use [this tool](https://www.whatsmydns.net/#NS/) to check the propagation. If you can't see at least some DNS servers reflecting your knary domain as the nameserver after 12 hours, you've done something wrong.

5. Create a `.env` file in the same directory as the knary binary and [configure](https://github.com/sudosammy/knary/tree/master/examples) it as necessary. You can also use environment variables to set these configurations. Environment variables will take precedence over the `.env` file.

6. __Optional__ For accepting TLS (HTTPS) connections set the `LETS_ENCRYPT=<email address>` variable and knary will automagically manage wildcard certificates for you (see [OPSEC note](#opsec-notes) below). Otherwise, you can specify the path to your own certificates with `TLS_CRT=<path>` and `TLS_KEY=<path>`.

7. Run the binary (via the provided [Docker container](#knary-docker), or in `tmux` / `screen`) and hope for output that looks something like this: 

![knary go-ing](https://github.com/sudosammy/knary/raw/master/screenshots/run.png "knary go-ing")

## Inbound Firewall Requirements
In its most common configuration, knary will bind to these ports. You must permit connections from **any** IP address to these ports on your knary host.

| Port | Reason |
| --------| -------- |
| 53 tcp & udp | DNS |
| 80 tcp | HTTP |
| 443 tcp | HTTPS |

## Allowing or denying matches
You **will** find systems that spam your knary even long after an engagement has ended. You will also find several DNS requests to mundane subdomains hitting your knary every day. To stop these from cluttering your notifications knary has a few features:

1. A simple text-based deny and/or allowlist (location specified with `DENYLIST_FILE` and/or `ALLOWLIST_FILE`). Add the subdomains, IP addresses, or User-Agents separated by a newline (case-insensitive):
```
knary.tld
www.knary.tld
171.244.140.247
test.dns.knary.tld
sam.knary.tld
```
If this were a denylist, it would stop knary from alerting on `www.knary.tld` but not `another.www.knary.tld`.

If this were an allowlist, knary would alert on exact matches (`sam.knary.tld`) and subdomain matches (`website1.sam.knary.tld`). Use `ALLOWLIST_STRICT=true` to prevent this fuzzy matching and only alert on hits to `sam.knary.tld`.

You can use both a deny and allowlist simultaneously. **Note:** wildcards in these files are not supported. An entry of `*.knary.tld` will match that string exactly.

2. The `DNS_SUBDOMAIN` configuration allows you to specify a subdomain that knary must fuzzy match (i.e. `*.DNS_SUBDOMAIN.knary.tld`) before alerting on DNS hits. This configuration does not affect HTTP(S) requests and remains primarily to mimic legacy knary v2 functionality. **Consider using a deny/allowlist instead.**

A configuration of `DNS_SUBDOMAIN=dns` would stop knary from alerting on DNS hits to `blah.knary.tld` but not `blah.dns.knary.tld`. A HTTP request to `blah.knary.tld` would still notify you unless prevented by an allow- or denylist.

Sample configurations can be found [in the examples](https://github.com/sudosammy/knary/tree/master/examples) with common subdomains to deny.

## knary Docker
Using knary in a container is as simple as creating your `.env` file (or setting environment variables in the `docker-compose.yaml` file) and running `sudo docker compose up -d`

## OPSEC notes
* Let's Encrypt will dox all the domains you are using with knary (and your `DNS_SUBDOMAIN`, `BURP_DOMAIN`, or `REVERSE_PROXY_DOMAIN` if you are using those configurations). This is due to these domains being included in the SAN certificate generated for you. A remote adversary can read the certificate and extract the list of domains within it. To avoid this, don't configure `LETS_ENCRYPT`. You can use self-signed certificates with `TLS_CRT=<path>` and `TLS_KEY=<path>`; however, many hosts will refuse to connect reducing your visibility of incoming HTTPS connections.
* With enough effort, knary is likely fingerprint-able by a remote host. i.e. it's plausible an adversary could determine you are running knary on a given host. This is because knary is not an RFC compliant nameserver (because doing so involves dark magic) and it likely behaves in an unusual / unique manner when compared to other nameservers.

## Supported Webhook Configurations
These are environment variables / `.env` file configurations. You can configure none, one, or many. Most common usage would be to configure one. Refer to [the examples](https://github.com/sudosammy/knary/tree/master/examples) for usage help.

* `SLACK_WEBHOOK` The full URL of the [incoming webhook](https://api.slack.com/custom-integrations/incoming-webhooks) for the Slack channel you want knary to notify
* `DISCORD_WEBHOOK` The full URL of the [Discord webhook](https://discordapp.com/developers/docs/resources/webhook) for the Discord channel you want knary to notify
* `TEAMS_WEBHOOK` The full URL of the [Microsoft Teams webhook](https://docs.microsoft.com/en-us/microsoftteams/platform/concepts/connectors/connectors-using#setting-up-a-custom-incoming-webhook) for the Teams channel you want knary to notify
* `PUSHOVER_TOKEN` The application token for the [Pushover Application](https://pushover.net/) you want knary to notify
* `PUSHOVER_USER` The user token of the Pushover user you want knary to notify
* `LARK_WEBHOOK` The full URL of the [webhook](https://www.feishu.cn/hc/en-US/articles/360024984973-Bot-Use-bots-in-groups) for the Lark/Feishu bot you want knary to notify
* `LARK_SECRET` The [secret token](https://www.feishu.cn/hc/en-US/articles/360024984973-Bot-Use-bots-in-groups) used to sign messages to your Lark/Feishu bot
* `TELEGRAM_CHATID` The [Telegram Bot](https://core.telegram.org/bots) chat ID you want knary to notify
* `TELEGRAM_BOT_TOKEN` The Telegram Bot token
