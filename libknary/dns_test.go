package libknary

import (
	"testing"
)

func TestInfoLog(t *testing.T) {
	ipaddr := "127.0.0.1"
	reverse := "example.com"
	name := "example"
	infoLog(ipaddr, reverse, name)

	// There are no assertions in this test at the moment
}
