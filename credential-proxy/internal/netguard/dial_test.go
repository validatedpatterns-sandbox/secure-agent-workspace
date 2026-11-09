package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestRejectsNonPublicAndClusterAnswersBeforeDial(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "169.254.169.254", "10.232.1.1", "172.231.0.1", "192.168.1.1", "100.100.100.200", "0.1.2.3", "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "8.8.8.8"} {
		t.Run(address, func(t *testing.T) {
			called := false
			d := Dialer{Deny: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24"), netip.MustParsePrefix("172.231.0.0/16")},
				LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP(address)}}, nil
				},
				Dial: func(context.Context, string, string) (net.Conn, error) {
					called = true
					return nil, errors.New("unexpected dial")
				}}
			if _, err := d.DialContext(context.Background(), "tcp", "api.example.test:443"); err == nil || called {
				t.Fatal("unsafe DNS answer reached dialer")
			}
		})
	}
}

func TestPinsPublicAnswerWithoutSecondLookup(t *testing.T) {
	lookups := 0
	d := Dialer{LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	},
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			if address != "93.184.216.34:443" {
				t.Fatal("dial was not pinned to verified IP")
			}
			return nil, errors.New("synthetic failure")
		}}
	_, _ = d.DialContext(context.Background(), "tcp", "api.example.test:443")
	if lookups != 1 {
		t.Fatal("unexpected DNS lookups")
	}
}
