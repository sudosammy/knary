# Configuration Options & Example Files

## Sample Files
* `default_env` - A recommended quick start configuration file with Let's Encrypt configuration
* `burp_env` - A recommended quick start configuration file if you are also using Burp Collaborator on the same server as knary
* `multidomain_env` - An example of how to specify multiple knary domains. Domains must be comma-delimited. Whitespace is stripped automatically
* `allowlist.txt` - This is an example allowlist showing how knary could be used with your team's names. This has the added benefit of allowing your team to configure [keyword notifications](https://slack.com/intl/en-au/help/articles/201355156-Configure-your-Slack-notifications#keyword-notifications) in Slack
* `denylist.txt` - If you are not going to use an allowlist, this is a good starting set of subdomains you should consider denying. Setting [DNS_SUBDOMAIN](#optional-configurations) will cut down the noise to your knary too. Find & Replace `knary.tld` with your knary domain
* `zone_file.txt` - Although an uncommon configuration, this file demonstrates the proper format for configuring a Zone file for custom responses to DNS queries made to knary

## Minimum Necessary Configuration
* `DNS` Enable/Disable the DNS canary (true/false)
* `HTTP` Enable/Disable the HTTP canary (true/false)
* `BIND_ADDR` The IP address you want knary to listen on. Example input: `0.0.0.0` to bind to all addresses available
* `CANARY_DOMAIN` The domain + TLD to match canary hits on. Example input: `mycanary.com` (knary will match `*.mycanary.com`). Multiple domains can be provided comma-delimited. Example input: `mycanary.com,knarytwo.zyz,knary3.io`
* `*_WEBHOOK` One (or many) webhooks for knary to alert. Refer to the [webhook section in the README](https://github.com/sudosammy/knary#supported-webhook-configurations) for options

## Recommended Optional Configurations
* `LETS_ENCRYPT` Enable Let's Encrypt management of your knary domain. If you do not configure this, or `TLS_*` as [detailed below](#optional-configurations), knary will only listen on port 80 and notify of HTTP hits. Example input: `myemailaddress@gmail.com`
* `LOG_FILE` Location for a file that knary will log greppable and timestamped warnings/errors. Example input: `/var/log/knary.log` or `knary.log` for current working directory
* `ALLOWLIST_FILE` Location for a file containing case-insensitive subdomains or IP addresses (separated by newlines) that should trigger a notification for knary (unless also included in the denylist). Example input: `allowlist.txt`
* `DENYLIST_FILE` Location for a file containing case-insensitive subdomains or IP addresses (separated by newlines) that should be ignored by knary and not logged or notified. Example input: `denylist.txt` 

## Burp Collaborator Configuration
If you are running Burp Collaborator on the same server as knary, you will need to configure the following.
* `BURP_DOMAIN` The domain + TLD to match Collaborator hits on (e.g. `burp.knary.tld`).
* `BURP_DNS_PORT` Local Burp Collaborator DNS port. This can't be `53` because knary listens on that one! Change Collaborator config to be something like `8053`, and set this to `8053`
* `BURP_HTTP_PORT` Much like the above - set to `8080` (or whatever you set the Burp HTTP port to be)
* `BURP_HTTPS_PORT` Much like the above - set to `8443` (or whatever you set the Burp HTTPS port to be)
* `BURP_INT_IP` __Optional__ The internal IP address that Burp Collaborator is bound to. In most cases this will be `127.0.0.1` (which is the default); however, if you run knary in Docker you may need to set this to the Burp Collaborator IP address reachable from within the knary container

## Optional Configurations
* `TLS_*` (CRT/KEY). If you're not using the `LETS_ENCRYPT` configuration use these environment variables to configure the location of your certificate and private key for accepting TLS (HTTPS) requests. Example input `TLS_KEY=certs/knary.key` & `TLS_CRT=certs/knary.crt`
* `DEBUG` Enable/Disable displaying incoming requests in the terminal and some additional info. Default disabled (true/false)
* `ALLOWLIST_STRICT` Set to `true` to prevent fuzzy matching on allowlist items and only alert on exact matches
* `LE_ENV` Set to `staging` to use the Let's Encrypt's staging environment. Useful if you are testing configurations with Let's Encrypt and do not want to hit the rate limit
* `EXT_IP` The IP address the DNS canary will answer `A` questions with. By default knary will use the nameserver glue record. Setting this option will overrule that behaviour
* `DENYLIST_ALERTING` By default knary will alert on items in the denylist that haven't triggered in >14 days. Set to `false` to disable this behaviour
* `DNS_SUBDOMAIN` Tell knary to only notify on `*.<DNS_SUBDOMAIN>.<CANARY_DOMAIN>` DNS hits. This is useful if you your webhook is getting too noisy with DNS hits to your knary TLD and you do not maintain an allow or denylist. Setting this configuration will mimic how knary operated prior to version 3. Example input: `dns`
* `ZONE_FILE` knary supports responding to DNS requests based on an RFC 1034/1035 compliant zone file. Example input: `zone_file.txt`

## Note about editing configuration and Let's Encrypt
If you have previously been running knary with Let's Encrypt and have now configured Burp Collaborator or `DNS_SUBDOMAIN`, you should delete the files in the `certs/` folder so that knary can re-generate certificates that include these subdomains as a SAN. Otherwise knary may exhibit strange behaviour / failures when attempting to renew the certificate.