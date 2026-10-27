package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeWG(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "x.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseWGFileFull(t *testing.T) {
	f, err := parseWGFile(writeWG(t, `
# a comment
[Interface]
PrivateKey = `+keyA+`
ListenPort = 51820
Address = 10.200.0.2/24, fd00::2/128
MTU = 1400

[Peer]
PublicKey = `+keyB+`
PresharedKey = `+keyA+`
Endpoint = example.com:51820
AllowedIPs = 10.20.0.10/32, 0.0.0.0/0
PersistentKeepalive = 25
`))
	if err != nil {
		t.Fatal(err)
	}
	if f.PrivateKey != keyA || f.ListenPort != 51820 || f.MTU != 1400 {
		t.Errorf("interface = %+v", f)
	}
	if len(f.Addresses) != 2 {
		t.Errorf("addresses = %v", f.Addresses)
	}
	if f.Peer.PublicKey != keyB || f.Peer.PresharedKey != keyA || f.Peer.Endpoint != "example.com:51820" ||
		f.Peer.PersistentKeepalive != 25 || len(f.Peer.AllowedIPs) != 2 {
		t.Errorf("peer = %+v", f.Peer)
	}
	if len(f.Warnings) != 0 {
		t.Errorf("warnings = %v", f.Warnings)
	}
}

func TestParseWGFileIgnoresWGQuickKeysWithWarning(t *testing.T) {
	f, err := parseWGFile(writeWG(t, `
[Interface]
PrivateKey = `+keyA+`
Address = 10.200.0.2/24
DNS = 1.1.1.1
Table = off
PostUp = echo pwned; rm -rf /
SaveConfig = true
MysteryKey = zzz

[Peer]
PublicKey = `+keyB+`
AllowedIPs = 10.20.0.10/32
`))
	if err != nil {
		t.Fatal(err)
	}
	// DNS, Table, PostUp, SaveConfig + the unknown key: 5 warnings,
	// and parsing succeeds (hooks are ignored, never executed).
	if len(f.Warnings) != 5 {
		t.Errorf("warnings = %v, want 5", f.Warnings)
	}
	joined := strings.Join(f.Warnings, "\n")
	if !strings.Contains(joined, "PostUp") || !strings.Contains(joined, "never executed") {
		t.Errorf("hook warning should call out PostUp and non-execution: %v", f.Warnings)
	}
}

func TestParseWGFileErrors(t *testing.T) {
	cases := map[string]string{
		"two peers": `
[Interface]
PrivateKey = ` + keyA + `
[Peer]
PublicKey = ` + keyB + `
[Peer]
PublicKey = ` + keyB + `
`,
		"no peer": `
[Interface]
PrivateKey = ` + keyA + `
`,
		"no private key": `
[Interface]
ListenPort = 51820
[Peer]
PublicKey = ` + keyB + `
`,
		"bad listen port": `
[Interface]
PrivateKey = ` + keyA + `
ListenPort = soon
[Peer]
PublicKey = ` + keyB + `
`,
		"key outside section": `
PrivateKey = ` + keyA + `
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseWGFile(writeWG(t, body)); err == nil {
				t.Error("accepted, want parse error")
			}
		})
	}
}
