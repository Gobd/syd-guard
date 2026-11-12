package lima

import (
	"reflect"
	"testing"
)

func TestShellArgsPreserveArgv(t *testing.T) {
	command := []string{"sydguard", "doctor", "--backend", "native", "argument with spaces; $(not shell)"}
	got, err := ShellArgs("ai-sandbox", command)
	want := append([]string{"shell", "--workdir", "/tmp", "ai-sandbox"}, command...)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v/%v", got, err)
	}
}

func TestRejectInvalidInstanceAndEmptyCommand(t *testing.T) {
	for _, name := range []string{"", "../other", "--help", "my vm", "vm;echo x"} {
		if _, err := ShellArgs(name, []string{"true"}); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	if _, err := ShellArgs("valid", nil); err == nil {
		t.Fatal("accepted empty command")
	}
}
