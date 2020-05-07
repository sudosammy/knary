package libknary

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestStringContains(t *testing.T) {
	string1 := "gokuKaioKen"
	string2 := "goku"

	string3 := "Naruto"
	string4 := "zzz"

	if val := stringContains(string1, string2); val != true {
		//cant think of another meaningful error message, its just broken!
		t.Errorf("String contains is broken")
	}

	if val := stringContains(string3, string4); val == true {
		t.Errorf("String contains is broken")
	}
}

//simply clear the contents of a particular file
// in this case blacklist_test.txt
func clearFileContent(file string) {
	testFile, err := os.OpenFile(file, os.O_RDWR, 0666)
	if err != nil {
		panic(err)
	}

	defer testFile.Close()
	testFile.Truncate(0)
	testFile.Seek(0, 0)
}

//write some specific data to some specific file !
func writeDataToFile(data string, file string) {
	entry := []byte(data)
	err := ioutil.WriteFile(file, entry, 0644)
	if err != nil {
		panic(err)
	}
}

func TestInBlacklist(t *testing.T) {
	os.Setenv("BLACKLIST_FILE", "blacklist_test.txt")
	LoadBlacklist()
	dom := "mycanary.com"
	//first test is for empty blacklist file
	val := inBlacklist()

	if val == true {
		t.Errorf("Expected false since file is emtpy, Got true(there is a match)")
	}

	//second test is for an actual entry
	writeDataToFile("mycanary.com", "blacklist_test.txt")
	LoadBlacklist()
	val = inBlacklist(dom)

	if val == false {
		t.Errorf("Expected true since entry is in blacklist but got false")
	}

	//test case for no match
	dom = "google.com"
	clearFileContent("blacklist_test.txt")
	writeDataToFile("mycanary.com", "blacklist_test.txt")
	LoadBlacklist()
	val = inBlacklist(dom)

	if val == true {
		t.Errorf("Expected false since there is no match but got true")
	}

	// last test case to check if it matches x.mycanary.com when blacklist only says mycanary.com

	dom = "dns.mycanary.com"
	val = inBlacklist(dom)

	if val == true {
		t.Errorf("Expected false since it shouldnt match dns.mycanary.com when blacklist says mycanary.com")
	}
	clearFileContent("blacklist_test.txt")

}
