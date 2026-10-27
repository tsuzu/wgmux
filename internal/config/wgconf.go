package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// This file parses standard wg-quick configuration files so users
// can hand wgmux the files they already have, unmodified:
//
//	[Interface]            the local side of one tunnel
//	PrivateKey = ...       -> the peer device's private key
//	ListenPort = ...       -> the peer device's listen port
//	Address = 10.0.0.2/24  -> candidate front address (see Mux docs)
//	[Peer]                 the remote site
//	PublicKey / PresharedKey / AllowedIPs / Endpoint / PersistentKeepalive
//
// Exactly one [Peer] section per file is supported (v1): one file
// describes one tunnel, which is how wg-quick configs for
// point-to-point site links are written anyway.
//
// wg-quick-only keys (DNS, Table, MTU excepted below, and the hook
// commands PreUp/PostUp/PreDown/PostDown, SaveConfig) and unknown
// keys are IGNORED with a warning. Hook commands are NEVER executed.

type wgFile struct {
	PrivateKey string
	ListenPort int
	Addresses  []string
	MTU        int
	Peer       wgFilePeer
	Warnings   []string
}

type wgFilePeer struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          []string
	Endpoint            string
	PersistentKeepalive int
}

// wgIgnoredKeys are keys wgmux deliberately does not act on. The
// hook keys must never be executed — wgmux reads configuration, it
// does not run the user's shell commands.
var wgIgnoredKeys = map[string]bool{
	"dns": true, "table": true, "fwmark": true, "saveconfig": true,
	"preup": true, "postup": true, "predown": true, "postdown": true,
}

func parseWGFile(path string) (*wgFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f := &wgFile{}
	section := ""
	peerSections := 0
	seenInterface := false
	warn := func(format string, args ...interface{}) {
		f.Warnings = append(f.Warnings, fmt.Sprintf("%s: %s", path, fmt.Sprintf(format, args...)))
	}
	for lineno, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("%s:%d: malformed section header %q", path, lineno+1, line)
			}
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				seenInterface = true
			case "peer":
				peerSections++
				if peerSections > 1 {
					return nil, fmt.Errorf("%s: more than one [Peer] section; wgmux v1 takes exactly one peer per wg config file", path)
				}
			default:
				return nil, fmt.Errorf("%s:%d: unknown section [%s]", path, lineno+1, section)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected key = value, got %q", path, lineno+1, line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		lk := strings.ToLower(key)
		if section == "" {
			return nil, fmt.Errorf("%s:%d: key %q outside any section", path, lineno+1, key)
		}
		if wgIgnoredKeys[lk] {
			warn("ignoring wg-quick key %s (not applicable to wgmux; hook commands are never executed)", key)
			continue
		}
		intVal := func() (int, error) {
			n, err := strconv.Atoi(value)
			if err != nil {
				return 0, fmt.Errorf("%s:%d: %s = %q is not a number", path, lineno+1, key, value)
			}
			return n, nil
		}
		splitList := func() []string {
			var out []string
			for _, part := range strings.Split(value, ",") {
				if part = strings.TrimSpace(part); part != "" {
					out = append(out, part)
				}
			}
			return out
		}
		var perr error
		switch section + "." + lk {
		case "interface.privatekey":
			f.PrivateKey = value
		case "interface.listenport":
			f.ListenPort, perr = intVal()
		case "interface.address":
			f.Addresses = append(f.Addresses, splitList()...)
		case "interface.mtu":
			f.MTU, perr = intVal()
		case "peer.publickey":
			f.Peer.PublicKey = value
		case "peer.presharedkey":
			f.Peer.PresharedKey = value
		case "peer.allowedips":
			f.Peer.AllowedIPs = append(f.Peer.AllowedIPs, splitList()...)
		case "peer.endpoint":
			f.Peer.Endpoint = value
		case "peer.persistentkeepalive":
			f.Peer.PersistentKeepalive, perr = intVal()
		default:
			warn("ignoring unknown key %s in [%s]", key, section)
		}
		if perr != nil {
			return nil, perr
		}
	}
	if !seenInterface {
		return nil, fmt.Errorf("%s: no [Interface] section", path)
	}
	if peerSections == 0 {
		return nil, fmt.Errorf("%s: no [Peer] section", path)
	}
	if f.PrivateKey == "" {
		return nil, fmt.Errorf("%s: [Interface] PrivateKey is missing (wgmux needs the device key from the file)", path)
	}
	return f, nil
}
