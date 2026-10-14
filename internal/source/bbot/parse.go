package bbot

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/model"
)

func parseEvent(raw []byte, name string) (model.AssetInput, bool, error) {
	var e event
	if err := json.Unmarshal(raw, &e); err != nil || e.Type == "" {
		return model.AssetInput{}, false, errors.New("invalid JSON event")
	}
	var kind model.AssetKind
	switch e.Type {
	case "DNS_NAME":
		kind = model.KindHostname
	case "IP_ADDRESS":
		kind = model.KindIP
	case "URL":
		kind = model.KindURL
	case "OPEN_TCP_PORT":
		kind = model.KindService
	default:
		return model.AssetInput{}, false, nil
	}
	var data string
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return model.AssetInput{}, false, errors.New("event data must be a string")
	}
	key, ok := eventKey(kind, data)
	if !ok {
		return model.AssetInput{}, false, errors.New("invalid event data")
	}
	return model.AssetInput{Kind: kind, Key: key, Source: name, Attrs: provenance(e)}, true, nil
}

func eventKey(kind model.AssetKind, raw string) (string, bool) {
	switch kind {
	case model.KindHostname:
		return hostname(raw)
	case model.KindIP:
		ip, err := netip.ParseAddr(raw)
		return ip.Unmap().String(), err == nil && ip.Zone() == ""
	case model.KindURL:
		return safeURL(raw)
	case model.KindService:
		host, port, err := net.SplitHostPort(raw)
		if err != nil {
			return "", false
		}
		port, ok := normalizePort(port)
		if !ok {
			return "", false
		}
		host, ok = canonicalHost(host)
		return net.JoinHostPort(host, port) + "/tcp", ok
	}
	return "", false
}

func hostname(raw string) (string, bool) {
	s := strings.TrimSuffix(strings.ToLower(raw), ".")
	if len(s) == 0 || len(s) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false // DNS_NAME is not an alternate encoding of IP_ADDRESS.
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return "", false
			}
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", false // A numeric top-level label is not a DNS hostname.
	}
	return s, true
}

func canonicalHost(raw string) (string, bool) {
	if ip, err := netip.ParseAddr(raw); err == nil {
		return ip.Unmap().String(), ip.Zone() == ""
	}
	return hostname(raw)
}

func normalizePort(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	p, err := strconv.Atoi(raw)
	if err != nil || p < 1 || p > 65535 {
		return "", false
	}
	return strconv.Itoa(p), true
}

func safeURL(raw string) (string, bool) {
	if len(raw) > 4096 {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") || strings.HasSuffix(u.Host, ":") {
		return "", false
	}
	host, ok := canonicalHost(u.Hostname())
	if !ok {
		return "", false
	}
	port := u.Port()
	if port != "" {
		port, ok = normalizePort(port)
		if !ok {
			return "", false
		}
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	u.User, u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = nil, "", "", "", false
	return u.String(), true
}
