# knary - A simple HTTP(S) and DNS Canary

[![Build Status](https://travis-ci.org/sudosammy/knary.svg?branch=master)](https://travis-ci.org/sudosammy/knary)  [![Coverage Status](https://coveralls.io/repos/github/sudosammy/knary/badge.svg?branch=master)](https://coveralls.io/github/sudosammy/knary?branch=master)

>Like "Canary" but more hipster, which means better 😎😎😎

⚠️ **Note: Upgrading from version 2? You need to change your DNS setup to make use of new knary features. See step [#2 and #3](#setup) below. You may also want to configure [DNS_SUBDOMAIN](https://github.com/sudosammy/knary/tree/master/examples#likely-recommended-optional-configurations) to mimic how knary operated previously.** ⚠️

knary is a canary token server that notifies a Slack/Discord/Teams/Lark channel (or other webhook) when incoming HTTP(S) or DNS requests match a given domain or any of its subdomains. It also supports functionality useful in offensive engagements including subdomain denylisting, working with Burp Collaborator, and easy TLS certificate creation.

![knary canary-ing](https://github.com/sudosammy/knary/raw/master/screenshots/canary.gif "knary canary-ing")

## Why is this useful?

Redteamers use canaries to be notified when someone (or *something*) attempts to interact with a server they control. Canaries help provide visibility over processes that were previously unknown. They can help find areas to probe for RFI or SSRF vulnerabilities, disclose previously unknown servers, provide evidence of an intercepting device, or just announce someone interacting with your server.

Defenders also use canaries as tripwires that can alert them of an attacker within their network by having the attacker announce themselves. If you are a defender, https://canarytokens.org might be what you’re looking for.

## Setup

1. Download the [applicable 64-bit knary binary](https://github.com/sudosammy/knary/releases) __OR__ build knary from source:

__Prerequisite:__ You need Go >=1.16 to build knary.
```
go get -u github.com/sudosammy/knary
```

2. Set your chosen knary domain nameserver(s) to point to a subdomain under itself; such as `ns.knary.tld`. If required, set multiple nameserver records such as `ns1.knary.tld`, `ns2.knary.ltd`.

3. Create a "Glue Record", sometimes referred to as "Nameserver Registration" or "Nameserver IP address" to point to your knary server. This is what it looks like in `name.com`:

 ![Setting a glue record](https://github.com/sudosammy/knary/raw/master/screenshots/nameserver-ip.png "Setting a glue record")

If your registry requires you to have multiple nameservers with different IP addresses, set the second nameserver to an IP address such as `8.8.8.8` or `1.1.1.1`. 

**Note:** You may need to raise a support ticket to have step #2 and #3 performed by your registrar. 

4. This will take some time to propagate, so go setup your [webhook](#supported-webhook-configurations).

5. Create a `.env` file in the same directory as the knary binary and [configure](https://github.com/sudosammy/knary/tree/master/examples) it as necessary. You can also use environment variables to set these configurations. Environment variables will take precedence over the `.env` file.

6. __Optional__ For accepting TLS (HTTPS) connections set the `LETS_ENCRYPT=<email address>` variable and knary will automagically manage wildcard certificates for you. Otherwise, you can specify the path to your own certificates with `TLS_CRT=<path>` and `TLS_KEY=<path>`.

7. Run the binary (probably in `screen`, `tmux`, or similar) and hope for output that looks something like this: 

![knary go-ing](https://github.com/sudosammy/knary/raw/master/screenshots/run.png "knary go-ing")

## Denying matches
You **will** find systems that spam your knary even long after an engagement has ended. You will also find several DNS requests to mundane subdomains hitting your knary every day. To stop these from cluttering your notifications knary has two features:

1. A simple text-based denylist (location specified with `DENYLIST_FILE`). Add the offending subdomains or IP addresses separated by a newline (case-insensitive):
```
knary.tld
www.knary.tld
171.244.140.247
test.dns.knary.tld
```
This would stop knary from alerting on `www.knary.tld` but not `another.www.knary.tld`. **Note:** wildcards are not supported. An entry of `*.knary.tld` will match that string exactly.

2. The `DNS_SUBDOMAIN` configuration allows you to specify that knary should only alert on DNS hits that are `*.<DNS_SUBDOMAIN>.knary.tld`.

A configuration of `DNS_SUBDOMAIN=dns` would stop knary from alerting on DNS hits to `blah.knary.tld` but not `blah.dns.knary.tld`. This configuration only affects DNS traffic. A HTTP request to `blah.knary.tld` would still notify you unless prevented by the denylist. Use a combination of both deny methods if you wish to prevent this.

Sample configurations can be found [in the examples](https://github.com/sudosammy/knary/tree/master/examples) with common subdomains to deny.

## knary Docker
Using knary in a container is as simple as creating your `.env` file (or setting environment variables in the `docker-compose.yaml` file) and running `sudo docker compose up -d`

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
