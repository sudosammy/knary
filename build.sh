#!/usr/bin/env bash

set -euo pipefail

# https://www.digitalocean.com/community/tutorials/how-to-build-go-executables-for-multiple-platforms-on-ubuntu-16-04
version=${1:-}
if [[ -z "$version" ]]; then
	echo "usage: $0 <version>"
	echo "i.e. $0 4.0.1"
	exit 1
fi

platforms=("windows/amd64" "windows/arm64" "linux/amd64" "linux/arm64" "darwin/amd64" "darwin/arm64")

for platform in "${platforms[@]}"
do
	IFS=/ read -r goos goarch <<< "$platform"
	output_name="knary-${version}-${goos}-${goarch}"
	if [[ "$goos" == "windows" ]]; then
		output_name+=".exe"
	fi

	echo "Building $goos/$goarch version..."
	env GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -tags timetzdata -o "$output_name" .
done
