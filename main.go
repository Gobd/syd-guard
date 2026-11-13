// Command sydguard runs AI agents under upstream Syd with a browser UI for
// approving file and network access, applied live to the running agent.
package main

import (
	"fmt"
	"os"
	"strings"
)

const usage = `sydguard — run a command under Syd, approve access in a browser.

  sydguard [flags] -- command [args...]   run under the project's rules
  sydguard --learn -- command [args...]   allow everything, record suggestions
  sydguard ui                             open the approvals UI
  sydguard daemon                         run the UI/proxy daemon (auto-started)

Flags (macOS → Lima):
  --vm NAME     Lima instance (default $SYDGUARD_VM or ai-sandbox)
  --lima FILE   Lima config used if the VM must be created

Rules: <project>/.sydguard.json (project = git root), plus
~/.config/sydguard/global.json. The sandbox can never write either.
`

type opts struct {
	vm, limaFile, command string
	learn                 bool
	args                  []string
}

func parse(argv []string) (opts, error) {
	var o opts
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		value := func() (string, error) {
			if k, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(k, "--") {
				return v, nil
			}
			if i+1 >= len(argv) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return argv[i], nil
		}
		var err error
		switch {
		case a == "--":
			o.args = argv[i+1:]
			return o, nil
		case a == "--learn":
			o.learn = true
		case a == "--vm" || strings.HasPrefix(a, "--vm="):
			o.vm, err = value()
		case a == "--lima" || strings.HasPrefix(a, "--lima="):
			o.limaFile, err = value()
		case a == "-h" || a == "--help" || a == "help":
			o.command = "help"
			return o, nil
		case strings.HasPrefix(a, "-"):
			return o, fmt.Errorf("unknown flag %s", a)
		case o.command == "" && (a == "ui" || a == "daemon" || a == "daemon-ensure" || a == "version"):
			o.command = a
		default:
			o.args = argv[i:]
			return o, nil
		}
		if err != nil {
			return o, err
		}
	}
	return o, nil
}

func main() {
	o, err := parse(os.Args[1:])
	if err != nil {
		fmt.Fprint(os.Stderr, err, "\n\n", usage)
		os.Exit(2)
	}
	switch {
	case o.command == "help" || (o.command == "" && len(o.args) == 0):
		fmt.Print(usage)
	case o.command == "version":
		fmt.Println(selfVersion())
	case isMac():
		os.Exit(limaMain(o))
	case o.command == "daemon":
		if err := runDaemon(); err != nil {
			os.Exit(fail(err))
		}
	case o.command == "daemon-ensure":
		started, err := ensureDaemon()
		if err != nil {
			os.Exit(fail(err))
		}
		token, _ := readToken()
		status := "running"
		if started {
			status = "started"
		}
		fmt.Println(status, uiURL(token))
	case o.command == "ui":
		if _, err := ensureDaemon(); err != nil {
			os.Exit(fail(err))
		}
		token, _ := readToken()
		fmt.Println(uiURL(token))
	default:
		os.Exit(cmdRun(o.args, o.learn))
	}
}
