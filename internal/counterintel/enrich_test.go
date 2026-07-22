package counterintel

import (
	"context"
	"errors"
	"testing"
)

func TestEnrich_CombinesBothSources(t *testing.T) {
	origRDAP, origGeo := rdapFetch, geoFetch
	defer func() { rdapFetch, geoFetch = origRDAP, origGeo }()

	rdapFetch = func(ctx context.Context, ip string) (string, string, error) {
		return "EXAMPLE-NET", "1.2.3.0 - 1.2.3.255", nil
	}
	geoFetch = func(ctx context.Context, ip string) (geoResult, error) {
		return geoResult{Country: "Netherlands", City: "Amsterdam", ASN: "AS1234 Example ISP", ISP: "Example ISP"}, nil
	}

	got := Enrich(context.Background(), "1.2.3.4")
	want := Intel{
		IP:      "1.2.3.4",
		Org:     "EXAMPLE-NET",
		Network: "1.2.3.0 - 1.2.3.255",
		Country: "Netherlands",
		City:    "Amsterdam",
		ASN:     "AS1234 Example ISP",
		ISP:     "Example ISP",
	}
	if got != want {
		t.Errorf("Enrich() = %+v, want %+v", got, want)
	}
}

func TestEnrich_OneSourceFailingStillReturnsTheOther(t *testing.T) {
	origRDAP, origGeo := rdapFetch, geoFetch
	defer func() { rdapFetch, geoFetch = origRDAP, origGeo }()

	rdapFetch = func(ctx context.Context, ip string) (string, string, error) {
		return "", "", errors.New("rdap unreachable")
	}
	geoFetch = func(ctx context.Context, ip string) (geoResult, error) {
		return geoResult{Country: "Germany"}, nil
	}

	got := Enrich(context.Background(), "5.6.7.8")
	if got.Org != "" || got.Network != "" {
		t.Errorf("Enrich() kept RDAP fields despite failure: %+v", got)
	}
	if got.Country != "Germany" {
		t.Errorf("Enrich().Country = %q, want %q", got.Country, "Germany")
	}
}

func TestEnrich_BothSourcesFailingLeavesJustIP(t *testing.T) {
	origRDAP, origGeo := rdapFetch, geoFetch
	defer func() { rdapFetch, geoFetch = origRDAP, origGeo }()

	rdapFetch = func(ctx context.Context, ip string) (string, string, error) {
		return "", "", errors.New("down")
	}
	geoFetch = func(ctx context.Context, ip string) (geoResult, error) {
		return geoResult{}, errors.New("down")
	}

	got := Enrich(context.Background(), "9.9.9.9")
	if got != (Intel{IP: "9.9.9.9"}) {
		t.Errorf("Enrich() = %+v, want just IP set", got)
	}
}
