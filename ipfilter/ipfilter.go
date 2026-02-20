package ipfilter

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/gophish/gophish/config"
	log "github.com/gophish/gophish/logger"
)

// Action represents the action to take when an IP is blacklisted
type Action string

const (
	// ActionIgnore logs the blacklist hit but allows the request to continue
	ActionIgnore Action = "ignore"
	// ActionNotFound returns a 404 response
	ActionNotFound Action = "notfound"
	// ActionRedirect redirects to a specified URL
	ActionRedirect Action = "redirect"
	// ActionFake serves a static fake page
	ActionFake Action = "fake"
)

// CheckResult contains the result of checking an IP against the blacklist
type CheckResult struct {
	Blacklisted bool
	Action      Action
	RedirectURL string
	FakePage    string
}

// blacklistEntry represents a parsed blacklist entry
type blacklistEntry struct {
	ranges      []*net.IPNet
	action      Action
	redirectURL string
	fakePage    string
}

// IPFilter provides IP blacklist checking functionality
type IPFilter struct {
	entries []blacklistEntry
}

// NewIPFilter creates a new IPFilter from configuration entries
func NewIPFilter(configEntries []config.BlacklistEntry) (*IPFilter, error) {
	filter := &IPFilter{
		entries: make([]blacklistEntry, 0, len(configEntries)),
	}

	for i, entry := range configEntries {
		// Validate action
		action := Action(entry.Action)
		if action != ActionIgnore && action != ActionNotFound && action != ActionRedirect && action != ActionFake {
			return nil, fmt.Errorf("invalid action '%s' in blacklist entry %d (must be 'ignore', 'notfound', 'redirect', or 'fake')", entry.Action, i)
		}

		// Validate redirect URL if action is redirect
		if action == ActionRedirect {
			if entry.RedirectURL == "" {
				return nil, fmt.Errorf("redirect_url required for blacklist entry %d with action 'redirect'", i)
			}
			// Validate URL format
			parsedURL, err := url.Parse(entry.RedirectURL)
			if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
				return nil, fmt.Errorf("invalid redirect_url '%s' in blacklist entry %d: must be a valid URL with scheme and host", entry.RedirectURL, i)
			}
		}

		// Validate fake page if action is fake
		if action == ActionFake {
			if entry.FakePage == "" {
				return nil, fmt.Errorf("fake_page required for blacklist entry %d with action 'fake'", i)
			}
		}

		// Parse IP range(s)
		ranges, err := parseIPRange(entry.IPRange)
		if err != nil {
			return nil, fmt.Errorf("error parsing ip_range '%s' in blacklist entry %d: %v", entry.IPRange, i, err)
		}

		filter.entries = append(filter.entries, blacklistEntry{
			ranges:      ranges,
			action:      action,
			redirectURL: entry.RedirectURL,
			fakePage:    entry.FakePage,
		})

		log.Debugf("Loaded blacklist entry %d: %d IP range(s) with action '%s'", i, len(ranges), action)
	}

	log.Infof("Loaded %d blacklist entries", len(filter.entries))
	return filter, nil
}

// Check tests if an IP address is blacklisted and returns the action to take
func (f *IPFilter) Check(ipStr string) CheckResult {
	// Parse the IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Invalid IP, not blacklisted
		return CheckResult{Blacklisted: false}
	}

	// Check each blacklist entry in order
	for _, entry := range f.entries {
		for _, ipRange := range entry.ranges {
			if ipRange.Contains(ip) {
				return CheckResult{
					Blacklisted: true,
					Action:      entry.action,
					RedirectURL: entry.redirectURL,
					FakePage:    entry.fakePage,
				}
			}
		}
	}

	// IP not found in blacklist
	return CheckResult{Blacklisted: false}
}

// parseIPRange parses an IP range string in various formats:
// - Single IP: "192.168.1.1"
// - CIDR: "10.0.0.0/24"
// - Hyphenated range: "10.0.0.1-10.0.0.5"
// - Comma-separated: "1.1.1.1,2.2.2.2,3.3.3.3"
func parseIPRange(rangeStr string) ([]*net.IPNet, error) {
	rangeStr = strings.TrimSpace(rangeStr)
	if rangeStr == "" {
		return nil, fmt.Errorf("empty IP range")
	}

	// Check for comma-separated list first
	if strings.Contains(rangeStr, ",") {
		return parseCommaSeparated(rangeStr)
	}

	// Check for hyphenated range
	if strings.Contains(rangeStr, "-") {
		return parseHyphenatedRange(rangeStr)
	}

	// Single IP or CIDR
	return parseSingleIPOrCIDR(rangeStr)
}

// parseSingleIPOrCIDR parses a single IP address or CIDR notation
func parseSingleIPOrCIDR(ipStr string) ([]*net.IPNet, error) {
	ipStr = strings.TrimSpace(ipStr)

	// Try parsing as CIDR first
	_, parsed, err := net.ParseCIDR(ipStr)
	if err == nil {
		return []*net.IPNet{parsed}, nil
	}

	// Try parsing as single IP (reuse pattern from dialer.go)
	singleIP := net.ParseIP(ipStr)
	if singleIP == nil {
		return nil, fmt.Errorf("'%s' is not a valid IP address or CIDR notation", ipStr)
	}

	// Convert single IP to CIDR notation
	var cidrStr string
	if singleIP.To4() != nil {
		cidrStr = ipStr + "/32" // IPv4
	} else {
		cidrStr = ipStr + "/128" // IPv6
	}

	_, parsed, err = net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("error converting IP '%s' to CIDR: %v", ipStr, err)
	}

	return []*net.IPNet{parsed}, nil
}

// parseCommaSeparated parses a comma-separated list of IPs or CIDRs
func parseCommaSeparated(listStr string) ([]*net.IPNet, error) {
	parts := strings.Split(listStr, ",")
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty comma-separated list")
	}

	allRanges := make([]*net.IPNet, 0, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue // Skip empty entries
		}

		ranges, err := parseSingleIPOrCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("error parsing item %d ('%s'): %v", i+1, part, err)
		}
		allRanges = append(allRanges, ranges...)
	}

	if len(allRanges) == 0 {
		return nil, fmt.Errorf("no valid IPs in comma-separated list")
	}

	return allRanges, nil
}

// parseHyphenatedRange parses an IP range like "10.0.0.1-10.0.0.5"
func parseHyphenatedRange(rangeStr string) ([]*net.IPNet, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("hyphenated range must have exactly one '-' separator")
	}

	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	startIP := net.ParseIP(startStr)
	endIP := net.ParseIP(endStr)

	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP '%s'", startStr)
	}
	if endIP == nil {
		return nil, fmt.Errorf("invalid end IP '%s'", endStr)
	}

	// Both must be same IP version
	startIPv4 := startIP.To4()
	endIPv4 := endIP.To4()

	if (startIPv4 != nil) != (endIPv4 != nil) {
		return nil, fmt.Errorf("start and end IPs must be same version (both IPv4 or both IPv6)")
	}

	// Only support IPv4 ranges (IPv6 ranges are too complex and rarely needed)
	if startIPv4 == nil {
		return nil, fmt.Errorf("hyphenated IPv6 ranges are not supported, use CIDR notation instead")
	}

	// Convert to uint32 for comparison and iteration
	start := ipToUint32(startIPv4)
	end := ipToUint32(endIPv4)

	if start > end {
		return nil, fmt.Errorf("start IP %s is greater than end IP %s", startStr, endStr)
	}

	// Safety check: limit to 1024 addresses to prevent memory exhaustion
	count := end - start + 1
	if count > 1024 {
		return nil, fmt.Errorf("hyphenated range spans %d addresses (max 1024): consider using CIDR notation instead", count)
	}

	// Generate /32 CIDR for each IP in range
	ranges := make([]*net.IPNet, 0, count)
	for i := start; i <= end; i++ {
		ip := uint32ToIP(i)
		_, parsed, err := net.ParseCIDR(ip.String() + "/32")
		if err != nil {
			return nil, fmt.Errorf("error creating CIDR for IP %s: %v", ip.String(), err)
		}
		ranges = append(ranges, parsed)
	}

	return ranges, nil
}

// ipToUint32 converts an IPv4 address to uint32
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIP converts a uint32 to an IPv4 address
func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
