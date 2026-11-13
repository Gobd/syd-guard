package managedlive

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestProtocolExcludesPrivilegedResourceSelectors(t *testing.T) {
	allowed := map[string]bool{"version": true, "kind": true, "ticket": true, "credential": true, "project": true, "profile": true, "session": true, "generation": true, "binding": true, "request_id": true, "sequence": true, "revision": true, "predecessor": true, "ready": true, "receipt": true, "phase": true, "engine_digest": true, "bank": true, "cleanup": true}
	for _, value := range []any{Ticket{}, Release{}, ApplySaved{}, StatusRequest{}, Ready{}, Applied{}, Status{}, Stopped{}, StartupStopped{}, Binding{}, BankReceipt{}, Receipt{}} {
		typ := reflect.TypeOf(value)
		for i := 0; i < typ.NumField(); i++ {
			name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
			if !allowed[name] {
				t.Errorf("unexpected %s selector in %s", name, typ.Name())
			}
		}
	}
}

// These source checks are guardrails, not runtime isolation proofs. This slice
// must remain unreachable until the later reviewed startup and watchdog gates.
func TestLiveSourceHasNoLauncherActivationOrListener(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); os.IsNotExist(err) {
		t.Skip("source tree unavailable in copied test binary")
	}
	files := []struct {
		path    string
		blocked map[string]bool
	}{
		{filepath.Join(root, "cmd/sydguard-launch-helper/main_linux.go"), map[string]bool{"newLiveAuthority": true, "ReceiveOperator": true, "Exchange": true}},
		{filepath.Join(root, "internal/managedlive/client_linux.go"), map[string]bool{"Listen": true, "ListenUnix": true, "ListenConfig": true, "Bind": true}},
		{filepath.Join(root, "internal/managedlive/protocol.go"), map[string]bool{"Listen": true, "ListenUnix": true, "ListenConfig": true, "Bind": true}},
	}
	for _, item := range files {
		node, err := parser.ParseFile(token.NewFileSet(), item.path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(node, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			switch f := call.Fun.(type) {
			case *ast.Ident:
				name = f.Name
			case *ast.SelectorExpr:
				name = f.Sel.Name
			}
			if item.blocked[name] {
				t.Errorf("unexpected %s call in %s", name, item.path)
			}
			return true
		})
	}
}
