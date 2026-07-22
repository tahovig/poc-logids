package counterintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Intel is the passive information gathered about a source IP, drawn
// entirely from public registries -- nothing here is derived from
// contacting the source IP itself.
type Intel struct {
	IP      string `json:"ip"`
	Org     string `json:"org,omitempty"`     // network/allocation holder, from RDAP
	Network string `json:"network,omitempty"` // allocated address range, from RDAP
	Country string `json:"country,omitempty"` // from GeoIP
	City    string `json:"city,omitempty"`    // from GeoIP
	ASN     string `json:"asn,omitempty"`     // e.g. "AS12345 Some ISP", from GeoIP
	ISP     string `json:"isp,omitempty"`     // from GeoIP
}

// lookupTimeout bounds each individual HTTP call so a slow or
// unresponsive registry can't stall enrichment.
const lookupTimeout = 3 * time.Second

var httpClient = &http.Client{Timeout: lookupTimeout}

// rdapFetch and geoFetch are package vars (not direct calls) so tests
// can substitute stubs -- no live network calls in the test suite,
// matching the reverse-DNS lookup pattern in internal/output.
var (
	rdapFetch = fetchRDAP
	geoFetch  = fetchGeo
)

// Enrich gathers passive intelligence about ip: RDAP for network/org
// ownership (keyless, IANA-standard bootstrap redirector), ip-api.com
// for geolocation and ASN/ISP (keyless, free tier). Both sources are
// best-effort and independent -- a failure in either still returns
// whatever the other found, rather than failing the whole lookup.
func Enrich(ctx context.Context, ip string) Intel {
	intel := Intel{IP: ip}

	if org, network, err := rdapFetch(ctx, ip); err == nil {
		intel.Org = org
		intel.Network = network
	}
	if geo, err := geoFetch(ctx, ip); err == nil {
		intel.Country = geo.Country
		intel.City = geo.City
		intel.ASN = geo.ASN
		intel.ISP = geo.ISP
	}
	return intel
}

// fetchRDAP queries the RDAP bootstrap redirector, which forwards to
// whichever regional registry (ARIN, RIPE, APNIC, ...) actually holds
// the allocation for ip. org falls back to the allocation handle if
// no network name is present; network is the allocated address range.
func fetchRDAP(ctx context.Context, ip string) (org, network string, err error) {
	url := fmt.Sprintf("https://rdap.org/ip/%s", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("rdap: unexpected status %d", resp.StatusCode)
	}

	var parsed struct {
		Name         string `json:"name"`
		Handle       string `json:"handle"`
		StartAddress string `json:"startAddress"`
		EndAddress   string `json:"endAddress"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", "", err
	}

	org = parsed.Name
	if org == "" {
		org = parsed.Handle
	}
	if parsed.StartAddress != "" && parsed.EndAddress != "" {
		network = fmt.Sprintf("%s - %s", parsed.StartAddress, parsed.EndAddress)
	}
	return org, network, nil
}

type geoResult struct {
	Country string
	City    string
	ASN     string
	ISP     string
}

// fetchGeo queries ip-api.com's free JSON endpoint for geolocation
// and ASN/ISP data. The free tier is HTTP-only (no HTTPS) -- fine
// here since nothing sensitive is being sent, only a public source IP
// that's already in the alert data.
func fetchGeo(ctx context.Context, ip string) (geoResult, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,city,isp,as", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return geoResult{}, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return geoResult{}, err
	}
	defer resp.Body.Close()

	var parsed struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Country string `json:"country"`
		City    string `json:"city"`
		ISP     string `json:"isp"`
		AS      string `json:"as"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return geoResult{}, err
	}
	if parsed.Status != "success" {
		return geoResult{}, fmt.Errorf("ip-api: %s", parsed.Message)
	}
	return geoResult{Country: parsed.Country, City: parsed.City, ASN: parsed.AS, ISP: parsed.ISP}, nil
}
