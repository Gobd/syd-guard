module github.com/Gobd/syd-guard

go 1.27.0

require (
	github.com/urfave/cli/v3 v3.14.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/nftables v0.3.0 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/sync v0.6.0 // indirect
)

replace github.com/vishvananda/netlink => ./third_party/netlink
