# Local privileged Go library patch

This is a local copy of `github.com/vishvananda/netlink` v1.3.1, not a Syd enforcement fork. Upstream: https://github.com/vishvananda/netlink, version v1.3.1. The original module zip's SHA-256 is `213c83dcc66cbeca2b83eca59d08649fa5ea96f463a8c014e8d6b6d5e601887e`; Go module checksum is `h1:3AEMt62VKqz90r0tmNhog0r/PpWKmrEShJU0wJW6bV0=`. The upstream LICENSE is retained. The root go.mod replaces this exact module with this copy; no global module cache is modified.

Changes from upstream:

* `nl/nl_linux.go`: in the selected `getNetlinkSocket` constructor, close the raw FD if setting nonblocking mode fails, and close the owning `os.File` on bind failure. A parameterized internal helper permits deterministic error-injection tests.
* `handle_linux.go`: `Handle.Close` keeps its private socket map rather than setting it to nil, preventing requests after close from becoming package-level requests and avoiding concurrent map mutation by close.
* `nl/nl_linux.go`: a request with a private socket map fails if its family is missing rather than creating an unscoped socket. Package-level requests, which have no private map, retain upstream behavior.
* `nl/socket_ownership_linux_test.go` and `handle_close_private_linux_test.go`: nonprivileged regressions for the changes.

Maintenance obligation: when changing or upgrading this dependency, compare these exact paths against upstream, re-evaluate the fixes and caller assumptions, run the selected nonprivileged regression tests, and remove or rebase this patch only after equivalent upstream behavior is verified. Other upstream entry points, including namespace restoration and Subscribe, are not repaired by this patch and must not be assumed fixed. The managed route caller deliberately avoids library namespace entry/restoration.
