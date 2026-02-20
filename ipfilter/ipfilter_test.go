package ipfilter

import (
	"net"
	"testing"

	"github.com/gophish/gophish/config"
)

func TestParseSingleIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"Valid IPv4", "192.168.1.1", false},
		{"Valid IPv4 localhost", "127.0.0.1", false},
		{"Valid IPv6", "::1", false},
		{"Valid IPv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false},
		{"Invalid IP", "999.0.0.0", true},
		{"Invalid format", "invalid", true},
		{"Empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseSingleIPOrCIDR(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSingleIPOrCIDR() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{"Valid /24", "10.0.0.0/24", false},
		{"Valid /16", "192.168.0.0/16", false},
		{"Valid /32", "192.168.1.1/32", false},
		{"Valid IPv6 /128", "::1/128", false},
		{"Valid IPv6 /10", "fe80::/10", false},
		{"Invalid CIDR", "10.0.0.0/33", true},
		{"Invalid format", "10.0.0.0/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseSingleIPOrCIDR(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSingleIPOrCIDR() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseHyphenatedRange(t *testing.T) {
	tests := []struct {
		name      string
		rangeStr  string
		wantCount int
		wantErr   bool
	}{
		{"Valid small range", "10.0.0.1-10.0.0.5", 5, false},
		{"Valid single IP", "10.0.0.1-10.0.0.1", 1, false},
		{"Valid large range", "10.0.0.1-10.0.0.255", 255, false},
		{"Too large range", "10.0.0.1-10.0.4.1", 0, true}, // > 1024
		{"Start > end", "10.0.0.5-10.0.0.1", 0, true},
		{"Invalid start IP", "invalid-10.0.0.5", 0, true},
		{"Invalid end IP", "10.0.0.1-invalid", 0, true},
		{"IPv6 range", "::1-::5", 0, true}, // IPv6 not supported
		{"Mixed versions", "10.0.0.1-::1", 0, true},
		{"No separator", "10.0.0.1", 0, true},
		{"Multiple separators", "10.0.0.1-10.0.0.5-10.0.0.10", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranges, err := parseHyphenatedRange(tt.rangeStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHyphenatedRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(ranges) != tt.wantCount {
				t.Errorf("parseHyphenatedRange() got %d ranges, want %d", len(ranges), tt.wantCount)
			}
		})
	}
}

func TestParseCommaSeparated(t *testing.T) {
	tests := []struct {
		name      string
		list      string
		wantCount int
		wantErr   bool
	}{
		{"Valid single IP", "1.1.1.1", 1, false},
		{"Valid two IPs", "1.1.1.1,2.2.2.2", 2, false},
		{"Valid three IPs", "1.1.1.1,2.2.2.2,3.3.3.3", 3, false},
		{"With spaces", "1.1.1.1, 2.2.2.2, 3.3.3.3", 3, false},
		{"Mixed IP and CIDR", "1.1.1.1,10.0.0.0/24", 2, false},
		{"Invalid IP in list", "1.1.1.1,invalid,2.2.2.2", 0, true},
		{"Empty list", "", 0, true},
		{"Only commas", ",,,", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranges, err := parseCommaSeparated(tt.list)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCommaSeparated() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(ranges) != tt.wantCount {
				t.Errorf("parseCommaSeparated() got %d ranges, want %d", len(ranges), tt.wantCount)
			}
		})
	}
}

func TestIPMatching(t *testing.T) {
	filter, err := NewIPFilter([]config.BlacklistEntry{
		{IPRange: "192.168.1.1", Action: "notfound"},
		{IPRange: "10.0.0.0/24", Action: "ignore"},
		{IPRange: "172.16.0.1-172.16.0.5", Action: "redirect", RedirectURL: "https://example.com"},
		{IPRange: "1.1.1.1,2.2.2.2,3.3.3.3", Action: "notfound"},
	})
	if err != nil {
		t.Fatalf("Failed to create filter: %v", err)
	}

	tests := []struct {
		name            string
		ip              string
		wantBlacklisted bool
		wantAction      Action
	}{
		// Single IP tests
		{"Exact match single IP", "192.168.1.1", true, ActionNotFound},
		{"No match single IP", "192.168.1.2", false, ""},

		// CIDR tests
		{"Match in CIDR start", "10.0.0.1", true, ActionIgnore},
		{"Match in CIDR middle", "10.0.0.100", true, ActionIgnore},
		{"Match in CIDR end", "10.0.0.254", true, ActionIgnore},
		{"No match outside CIDR", "10.0.1.1", false, ""},

		// Hyphenated range tests
		{"Match range start", "172.16.0.1", true, ActionRedirect},
		{"Match range middle", "172.16.0.3", true, ActionRedirect},
		{"Match range end", "172.16.0.5", true, ActionRedirect},
		{"No match before range", "172.16.0.0", false, ""},
		{"No match after range", "172.16.0.6", false, ""},

		// Comma-separated tests
		{"Match first in list", "1.1.1.1", true, ActionNotFound},
		{"Match second in list", "2.2.2.2", true, ActionNotFound},
		{"Match third in list", "3.3.3.3", true, ActionNotFound},
		{"No match in list", "4.4.4.4", false, ""},

		// Invalid IPs
		{"Invalid IP", "invalid", false, ""},
		{"Empty IP", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filter.Check(tt.ip)
			if result.Blacklisted != tt.wantBlacklisted {
				t.Errorf("Check(%s) blacklisted = %v, want %v", tt.ip, result.Blacklisted, tt.wantBlacklisted)
			}
			if result.Blacklisted && result.Action != tt.wantAction {
				t.Errorf("Check(%s) action = %v, want %v", tt.ip, result.Action, tt.wantAction)
			}
		})
	}
}

func TestActionValidation(t *testing.T) {
	tests := []struct {
		name    string
		entries []config.BlacklistEntry
		wantErr bool
	}{
		{
			name: "Valid ignore action",
			entries: []config.BlacklistEntry{
				{IPRange: "192.168.1.1", Action: "ignore"},
			},
			wantErr: false,
		},
		{
			name: "Valid notfound action",
			entries: []config.BlacklistEntry{
				{IPRange: "192.168.1.1", Action: "notfound"},
			},
			wantErr: false,
		},
		{
			name: "Valid redirect action with URL",
			entries: []config.BlacklistEntry{
				{IPRange: "192.168.1.1", Action: "redirect", RedirectURL: "https://example.com"},
			},
			wantErr: false,
		},
		{
			name: "Valid fake action with page",
			entries: []config.BlacklistEntry{
				{IPRange: "192.168.1.1", Action: "fake", FakePage: "static/fake.html"},
			},
			wantErr: false,
		},
		{
			name: "Invalid action",
			entries: []config.BlacklistEntry{
				{IPRange: "192.168.1.1", Action: "invalid"},
			},
			wantErr: true,
		},
		{
			name: "Redirect without URL",
			entries: []config.BlacklistEntry{
				{IPRange: "192.168.1.1", Action: "redirect"},
			},
			wantErr: true,
		},
		{
			name: "Redirect with invalid URL",
			entries: []config.BlacklistEntry{
				{IPRange: "192.168.1.1", Action: "redirect", RedirectURL: "not-a-url"},
			},
			wantErr: true,
		},
		{
			name: "Redirect with relative URL",
			entries: []config.BlacklistEntry{
				{IPRange: "192.168.1.1", Action: "redirect", RedirectURL: "/relative"},
			},
			wantErr: true,
		},
		{
			name: "Fake without page",
			entries: []config.BlacklistEntry{
				{IPRange: "192.168.1.1", Action: "fake"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewIPFilter(tt.entries)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewIPFilter() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRedirectURL(t *testing.T) {
	filter, err := NewIPFilter([]config.BlacklistEntry{
		{IPRange: "192.168.1.1", Action: "redirect", RedirectURL: "https://example.com/path?query=value"},
		{IPRange: "10.0.0.1", Action: "notfound"},
	})
	if err != nil {
		t.Fatalf("Failed to create filter: %v", err)
	}

	// Test redirect URL is preserved
	result := filter.Check("192.168.1.1")
	if !result.Blacklisted {
		t.Error("Expected IP to be blacklisted")
	}
	if result.Action != ActionRedirect {
		t.Errorf("Expected action redirect, got %s", result.Action)
	}
	expectedURL := "https://example.com/path?query=value"
	if result.RedirectURL != expectedURL {
		t.Errorf("Expected redirect URL %s, got %s", expectedURL, result.RedirectURL)
	}

	// Test non-redirect action has no URL
	result = filter.Check("10.0.0.1")
	if !result.Blacklisted {
		t.Error("Expected IP to be blacklisted")
	}
	if result.RedirectURL != "" {
		t.Errorf("Expected empty redirect URL for notfound action, got %s", result.RedirectURL)
	}
}

func TestFakePage(t *testing.T) {
	filter, err := NewIPFilter([]config.BlacklistEntry{
		{IPRange: "192.168.1.1", Action: "fake", FakePage: "static/fake.html"},
		{IPRange: "10.0.0.1", Action: "notfound"},
	})
	if err != nil {
		t.Fatalf("Failed to create filter: %v", err)
	}

	// Test fake page is preserved
	result := filter.Check("192.168.1.1")
	if !result.Blacklisted {
		t.Error("Expected IP to be blacklisted")
	}
	if result.Action != ActionFake {
		t.Errorf("Expected action fake, got %s", result.Action)
	}
	expectedPage := "static/fake.html"
	if result.FakePage != expectedPage {
		t.Errorf("Expected fake page %s, got %s", expectedPage, result.FakePage)
	}

	// Test non-fake action has no fake page
	result = filter.Check("10.0.0.1")
	if !result.Blacklisted {
		t.Error("Expected IP to be blacklisted")
	}
	if result.FakePage != "" {
		t.Errorf("Expected empty fake page for notfound action, got %s", result.FakePage)
	}
}

func TestEmptyBlacklist(t *testing.T) {
	filter, err := NewIPFilter([]config.BlacklistEntry{})
	if err != nil {
		t.Fatalf("Failed to create empty filter: %v", err)
	}

	result := filter.Check("192.168.1.1")
	if result.Blacklisted {
		t.Error("Expected no IPs to be blacklisted with empty filter")
	}
}

func TestFirstMatchWins(t *testing.T) {
	// When multiple entries match, first one should win
	filter, err := NewIPFilter([]config.BlacklistEntry{
		{IPRange: "192.168.1.1", Action: "notfound"},
		{IPRange: "192.168.0.0/16", Action: "ignore"}, // Would also match 192.168.1.1
	})
	if err != nil {
		t.Fatalf("Failed to create filter: %v", err)
	}

	result := filter.Check("192.168.1.1")
	if !result.Blacklisted {
		t.Error("Expected IP to be blacklisted")
	}
	if result.Action != ActionNotFound {
		t.Errorf("Expected first match action (notfound), got %s", result.Action)
	}
}

func TestIPv6Support(t *testing.T) {
	filter, err := NewIPFilter([]config.BlacklistEntry{
		{IPRange: "::1/128", Action: "notfound"},
		{IPRange: "fe80::/10", Action: "ignore"},
	})
	if err != nil {
		t.Fatalf("Failed to create filter: %v", err)
	}

	tests := []struct {
		name            string
		ip              string
		wantBlacklisted bool
		wantAction      Action
	}{
		{"IPv6 loopback", "::1", true, ActionNotFound},
		{"IPv6 link-local start", "fe80::1", true, ActionIgnore},
		{"IPv6 link-local middle", "fe80::dead:beef", true, ActionIgnore},
		{"IPv6 no match", "2001:db8::1", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filter.Check(tt.ip)
			if result.Blacklisted != tt.wantBlacklisted {
				t.Errorf("Check(%s) blacklisted = %v, want %v", tt.ip, result.Blacklisted, tt.wantBlacklisted)
			}
			if result.Blacklisted && result.Action != tt.wantAction {
				t.Errorf("Check(%s) action = %v, want %v", tt.ip, result.Action, tt.wantAction)
			}
		})
	}
}

func TestUint32Conversion(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"Start of range", "0.0.0.0"},
		{"Low IP", "10.0.0.1"},
		{"Mid IP", "192.168.1.1"},
		{"High IP", "255.255.255.255"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse IP
			ip := parseIPv4(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP %s", tt.ip)
			}

			// Convert to uint32 and back
			n := ipToUint32(ip)
			result := uint32ToIP(n)

			// Should match original
			if !ip.Equal(result) {
				t.Errorf("Round-trip conversion failed: %s -> %d -> %s", ip, n, result)
			}
		})
	}
}

// Helper function to parse IPv4
func parseIPv4(s string) net.IP {
	return net.ParseIP(s).To4()
}
