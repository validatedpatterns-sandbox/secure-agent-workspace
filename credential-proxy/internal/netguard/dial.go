// Package netguard pins each upstream connection to a checked DNS answer.
package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

type Dialer struct {
	LookupIP func(context.Context, string) ([]net.IPAddr, error)
	Dial     func(context.Context, string, string) (net.Conn, error)
	Deny     []netip.Prefix
}

var special = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("240.0.0.0/4"),
	// Transition mechanisms can conceal an embedded private IPv4 target.
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2002::/16"),
}

func (d Dialer) Allowed(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range append(append([]netip.Prefix{}, special...), d.Deny...) {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" || net.ParseIP(host) != nil {
		return nil, errors.New("invalid upstream target")
	}
	lookup := d.LookupIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	ips, err := lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("upstream DNS unavailable")
	}
	// Reject the entire answer set before dialing, including mixed public/private
	// answers. The checked IP, never the name, reaches the underlying dialer.
	for _, ip := range ips {
		if ip.Zone != "" || !d.Allowed(ip.IP) {
			return nil, errors.New("upstream address refused")
		}
	}
	dial := d.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	for _, ip := range ips {
		conn, err := dial(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, errors.New("upstream unavailable")
}
