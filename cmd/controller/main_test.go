package main

import (
	"bytes"
	goflag "flag"
	"testing"

	flag "github.com/spf13/pflag"

	"github.com/bitnami/sealed-secrets/pkg/controller"
)

func TestVersion(t *testing.T) {
	buf := bytes.NewBufferString("")
	testVersionFlags := flag.NewFlagSet("testVersionFlags", flag.ExitOnError)
	testNopFlags := goflag.NewFlagSet("nop", goflag.ExitOnError)
	err := mainE(buf, testVersionFlags, testNopFlags, []string{"--version"})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := buf.String(), "controller version: UNKNOWN\n"; got != want {
		t.Errorf("got: %q, want: %q", got, want)
	}
}

func TestKeyBackupURLFlagAndEnv(t *testing.T) {
	var f controller.Flags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	bindControllerFlags(&f, fs)
	if err := fs.Parse([]string{"--key-backup-url=file:///tmp/x"}); err != nil {
		t.Fatal(err)
	}
	if f.KeyBackupURL != "file:///tmp/x" {
		t.Errorf("flag not bound: %q", f.KeyBackupURL)
	}

	var g controller.Flags
	fs2 := flag.NewFlagSet("test2", flag.ContinueOnError)
	gofs := goflag.NewFlagSet("gotest2", goflag.ContinueOnError)
	t.Setenv("SEALED_SECRETS_KEY_BACKUP_URL", "awssm://p?region=r")
	bindFlags(&g, fs2, gofs)
	if err := fs2.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if g.KeyBackupURL != "awssm://p?region=r" {
		t.Errorf("env not bound: %q", g.KeyBackupURL)
	}
}
