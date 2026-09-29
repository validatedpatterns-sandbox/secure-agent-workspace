package main

import "testing"

func TestProfilesIsolateWorkspaces(t *testing.T){
	files:=map[string]string{
		"profiles__demo__one__workspace.yaml":"metadata:\n  name: one\n",
		"profiles__demo__one__sandbox.yaml":"spec:\n  sandboxes:\n    - name: same\n",
		"profiles__demo__two__workspace.yaml":"metadata:\n  name: two\n",
		"profiles__demo__two__sandbox.yaml":"spec:\n  sandboxes:\n    - name: same\n",
	}
	entries,err:=desiredEntries("saw.test","saw-a","vm","uid","/node",files,"1000")
	if err!=nil||len(entries)!=3{t.Fatalf("entries=%v err=%v",entries,err)}
	if entries[1].SpiffeId.Path==entries[2].SpiffeId.Path{t.Fatal("workspace identities collide")}
	if len(entries[0].Selectors)<2{t.Fatal("gateway must not use UID only")}
	if entries[1].Selectors[1].Value==entries[2].Selectors[1].Value{t.Fatal("workspace selectors collide")}
	for _,e:=range entries{if e.Admin||e.ParentId.Path!="/node"{t.Fatal("invalid authority")}}
}

func TestInvalidProfilesFailBeforeRegistration(t *testing.T){
	for _,name:=range []string{"../other","toolongforopenshellidentity","a/b"}{
		files:=map[string]string{"profiles__p__w__workspace.yaml":"metadata:\n  name: "+name+"\n"}
		if _,err:=desiredEntries("saw.test","ns","vm","uid","/node",files,"1000");err==nil{t.Fatalf("accepted %q",name)}
	}
}

func TestDisabledWorkspaceDoesNotRegisterSandboxes(t *testing.T){
	files:=map[string]string{"profiles__p__w__workspace.yaml":"spec:\n  enabled: false\n","profiles__p__w__sandbox.yaml":"spec:\n  sandboxes:\n    - name: ignored\n"}
	entries,err:=desiredEntries("saw.test","ns","vm","uid","/node",files,"1000")
	if err!=nil||len(entries)!=1{t.Fatalf("entries=%v err=%v",entries,err)}
}
