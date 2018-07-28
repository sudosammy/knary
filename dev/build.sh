#!/bin/bash

# https://www.digitalocean.com/community/tutorials/how-to-build-go-executables-for-multiple-platforms-on-ubuntu-16-04
package=$1
version=$2
if [[ -z "$package" ]]; then
	echo "usage: $0 main.go <version>"
	exit 1
fi
package_split=(${package//\// })

platforms=("windows/amd64" "linux/amd64" "darwin/amd64")

for platform in "${platforms[@]}"
do
	platform_split=(${platform//\// })
	GOOS=${platform_split[0]}
	GOARCH=${platform_split[1]}
	output_name='knary-'$version'-'$GOOS'-'$GOARCH
	if [ $GOOS = "windows" ]; then
		output_name+='.exe'
	fi  

	env GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build -o $output_name '../'$package
	if [ $? -ne 0 ]; then
		echo 'An error has occurred! Aborting the script execution...'
		exit 1
	fi
done