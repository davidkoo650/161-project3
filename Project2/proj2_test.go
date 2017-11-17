package proj2

import (
	"testing"
	"github.com/nweaver/cs161-p2/userlib"
)



// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T){
	t.Log("Initialization test")
	DebugPrint = true
	someUsefulThings()

	DebugPrint = false
	u, err := InitUser("alice","fubar")
	if err != nil {
		// t.Error says the test fails 
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
}

func TestStorage(t *testing.T){
	// And some more tests, because
	v, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", v)
}

func TestStoreLoad(t *testing.T){
	u, err := InitUser("alice","fubar")
	if err != nil {
		// t.Error says the test fails 
		t.Error("Failed to initialize user", err)
	}

	v, err := GetUser(u.Username, u.Password)
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	contents := []byte("contents")
	v.StoreFile("filename", contents)
	data, err := v.LoadFile("filename")
	if err != nil {
		t.Error("LoadFile failed", err)
	}
	if (!userlib.Equal(data, contents)) {
		t.Error("Failed to Store and Load correctly.")
	}

	data, err = v.LoadFile("filename")
	if err != nil {
		t.Error("LoadFile failed", err)
	}
	if (!userlib.Equal(data, contents)) {
		t.Error("Failed to Store and Load correctly.")
	}

	appendContents := []byte("append")
	contents = append(contents, appendContents[:]...)
	err = v.AppendFile("filename", appendContents)
	if err != nil {
		t.Error("AppendFile failed", err)
	}
	appendedData, err := v.LoadFile("filename")
	if err != nil {
		t.Error("LoadFile failed", err)
	}
	if (!userlib.Equal(appendedData, contents)) {
		t.Error("Failed to append correctly.")
	}

	b, err := InitUser("bob", "yoyo")
	if (err != nil) {
		t.Error("Failed to initialize user", err)	
	}

	/* Tested Init, Get, Store, Load, Append. Move on to Share, Receive, Revoke. */

	msgid, err := v.ShareFile("filename", "bob")
	if err != nil {
		t.Error("ShareFile failed.", err)
	}
	err = b.ReceiveFile("Babo", "alice", msgid)
	if (err != nil) {
		t.Error("ReceiveFile failed.", err)
	}
}
