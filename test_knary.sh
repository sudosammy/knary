#!/bin/bash

# https://stackoverflow.com/questions/394230/how-to-detect-the-os-from-a-bash-script/18434831
domain=$1
if [[ -z "$domain" ]]; then
	echo "usage: $0 mycanary.com"
	exit 1
fi

echo "----------------------------------"
echo "Tests running..."
echo "----------------------------------"

if [[ "$OSTYPE" == "linux-gnu" ]]; then
	curl "http://test.$domain"
	curl "https://test.$domain"
	dig "test.dns.$domain"

elif [[ "$OSTYPE" == "darwin"* ]]; then
	curl "http://test.$domain"
	curl "https://test.$domain"
	dig "test.dns.$domain"

elif [[ "$OSTYPE" == "cygwin" ]]; then
	curl "http://test.$domain"
	curl "https://test.$domain"
	nslookup "test.dns.$domain"

elif [[ "$OSTYPE" == "msys" ]]; then
	curl "http://test.$domain"
	curl "https://test.$domain"
	nslookup "test.dns.$domain"

elif [[ "$OSTYPE" == "win32" ]]; then
	# I'm not sure this can happen.
	nslookup "test.dns.$domain"

elif [[ "$OSTYPE" == "freebsd"* ]]; then
	curl "http://test.$domain"
	curl "https://test.$domain"
	dig "test.dns.$domain"
else
	echo "Unknown OS. Read script and run commands manually."
fi

echo "----------------------------------"
echo "Check your webhook(s) for 3 hits!"
echo "----------------------------------"