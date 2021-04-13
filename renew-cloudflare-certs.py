import sys
import requests
import os
import json
import time
import subprocess
def main(zone_name: str, config_file: str, propagation_time: int = 10):
    # Note: Cloudflare API Key will need Edit permissons for Zone.DNS and read for Zone.Zone
    assert zone_name.isascii(), "Punycode is unsupported"
    try:
        with open(config_file, "r") as f:
            cloudflare_api_token = f.readline().split("=")[1].strip()
    except:
        print(f"Cannot open config file {config_file}")
        sys.exit(1)
    cloudflare_api_base_url = "https://api.cloudflare.com/client/v4"
    with requests.Session() as s:
        s.headers.update({"Authorization": f"Bearer {cloudflare_api_token}"})
        # get zone id
        zones = s.get(f"{cloudflare_api_base_url}/zones?name={zone_name}").json()["result"]
        assert len(zones) == 1
        zone_id = zones[0]["id"]
        zone_records_endpoint = f"{cloudflare_api_base_url}/zones/{zone_id}/dns_records"
        # fetch NS records, record, remove NS, run shell, readd
        records = s.get(f"{zone_records_endpoint}?type=NS").json()["result"]
        print(records)
        for nameserver in records:
            s.delete(f"{zone_records_endpoint}/{nameserver['id']}")
            time.sleep(propagation_time)
            subprocess.call(["certbot", "certonly", "--dns-cloudflare", "--dns-cloudflare-credentials", config_file, "-d", f"*.{zone_name}", "-d", f"*.dns.{zone_name}"])
            s.post(zone_records_endpoint, json={
                "type": "NS",
                "name": nameserver["name"],
                "content": nameserver["content"],
                "proxied": False
            })
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: sudo {sys.argv[0]} zone_name cloudflare_token_file [propagation_time]")
        print(f"Example: sudo {sys.argv[0]} mycanary.com ~/cloudflare_token.ini")
        print(f"cloudflare_token.ini example: dns_cloudflare_api_token=XXXXXXXXXXXXXXXXXXX")
    else:
        propagation_time = 10
        if len(sys.argv) >= 4:
            propagation_time = int(sys.argv[3])
        main(sys.argv[1], sys.argv[2], propagation_time)