// Command sydguard runs AI agents under upstream Syd with a browser UI for
// approving file and network access, applied live to the running agent.
package main

import (
	"fmt"
	"os"
	"strings"
)

const usage = `sydguard — run a command under Syd, approve access in a browser.

  sydguard [flags] -- command [args...]   run under the rules file
  sydguard --learn -- command [args...]   allow everything, save what it used
  sydguard ui                             open the approvals UI
  sydguard doctor                         check the Syd engine and daemon

Flags:
  --rules NAME|FILE  rules file. Default <git root>/.sydguard.json;
                     NAME = <git root>/.sydguard/NAME.json; or any path.
                     Lets two agents in one folder use different rules.
  --learn            permissive run; saves what the agent used into the rules file
  --vm NAME          (macOS) Lima instance; default $SYDGUARD_VM or ai-sandbox
  --lima FILE        (macOS) Lima config used if the VM must be created;
                     default $SYDGUARD_LIMA or the built-in template

Global rules for every project: ~/.config/sydguard/global.json (on the Mac).
The sandbox can never write rules files; changes made outside sydguard must be
trusted before they're used.
`

type opts struct {
	vm, limaFile, rules, command string
	learn, fromMac               bool
	args                         []string
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
		flag, _, _ := strings.Cut(a, "=")
		var err error
		switch {
		case a == "--":
			o.args = argv[i+1:]
			return o, nil
		case a == "--learn":
			o.learn = true
		case a == "--from-mac":
			o.fromMac = true
		case flag == "--vm":
			o.vm, err = value()
		case flag == "--lima":
			o.limaFile, err = value()
		case flag == "--rules":
			o.rules, err = value()
		case a == "-h" || a == "--help" || a == "help":
			o.command = "help"
			return o, nil
		case strings.HasPrefix(a, "-"):
			return o, fmt.Errorf("unknown flag %s", a)
		case o.command == "" && (a == "ui" || a == "ui-server" || a == "daemon" || a == "daemon-ensure" || a == "version" || a == "doctor"):
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
	_ = selfVersion() // hash our binary now, before any upgrade replaces it
	switch {
	case o.command == "help" || (o.command == "" && len(o.args) == 0):
		fmt.Print(usage)
	case o.command == "version":
		fmt.Println(selfVersion())
	case o.command == "ui-server":
		if err := runUIServer(); err != nil {
			os.Exit(fail(err))
		}
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
		fmt.Println(map[bool]string{true: "started", false: "running"}[started])
	case o.command == "doctor":
		os.Exit(cmdDoctor())
	case o.command == "ui":
		if _, err := ensureDaemon(); err != nil {
			os.Exit(fail(err))
		}
		if _, err := ensureUIServer(); err != nil {
			os.Exit(fail(err))
		}
		token, _ := uiToken()
		openBrowser(uiURL(token))
		fmt.Println(uiURL(token))
	default:
		os.Exit(cmdRun(o))
	}
}
