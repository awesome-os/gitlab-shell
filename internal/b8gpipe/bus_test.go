package b8gpipe

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultBusAddressForOS(t *testing.T) {
	if got := DefaultBusAddressForOS("windows"); got != WindowsBusAddress {
		t.Fatalf("windows bus address = %q, want %q", got, WindowsBusAddress)
	}
	if got := DefaultBusAddressForOS("linux"); got != PosixBusAddress {
		t.Fatalf("linux bus address = %q, want %q", got, PosixBusAddress)
	}
	if got := DefaultBusAddressForOS("darwin"); got != PosixBusAddress {
		t.Fatalf("darwin bus address = %q, want %q", got, PosixBusAddress)
	}

	wantCurrent := PosixBusAddress
	if runtime.GOOS == "windows" {
		wantCurrent = WindowsBusAddress
	}
	if got := DefaultBusAddress(); got != wantCurrent {
		t.Fatalf("DefaultBusAddress() = %q, want %q", got, wantCurrent)
	}
}

func TestValidateBusAddress_RejectsB8G016LoopbackHTTP(t *testing.T) {
	forbidden := []string{
		"http://127.0.0.1:8080/api/v4/internal/allowed",
		"https://127.0.0.1:8443/internal",
		"http://localhost:3000/api/v4/internal/authorized_keys",
		"https://localhost:9000",
		"ws://127.0.0.1:8080/stream",
		"127.0.0.1:8080",
		"localhost:8080",
		"[::1]:8080",
		"tcp://127.0.0.1:8080",
		"http://[::1]:8080",
	}

	for _, addr := range forbidden {
		err := ValidateBusAddress(addr)
		if !errors.Is(err, ErrLoopbackHTTPForbidden) {
			t.Errorf("ValidateBusAddress(%q) error = %v, want ErrLoopbackHTTPForbidden (B8G016)", addr, err)
		}
	}
}

func TestValidateBusAddress_AcceptsPipesAndUnixSockets(t *testing.T) {
	allowed := []string{
		WindowsBusAddress,
		`\\.\pipe\sectium-dev`,
		PosixBusAddress,
		"/tmp/sectium-dev.sock",
		"unix:///run/b8g/host-bus.sock",
	}

	for _, addr := range allowed {
		if err := ValidateBusAddress(addr); err != nil {
			t.Errorf("ValidateBusAddress(%q) unexpected error: %v", addr, err)
		}
	}
}

func TestResolveBusAddressForOS(t *testing.T) {
	t.Setenv(EnvBusAddress, "")

	addr, err := ResolveBusAddressForOS("windows", "")
	if err != nil || addr != WindowsBusAddress {
		t.Fatalf("ResolveBusAddressForOS(windows) = (%q, %v), want (%q, nil)", addr, err, WindowsBusAddress)
	}

	addr, err = ResolveBusAddressForOS("linux", "")
	if err != nil || addr != PosixBusAddress {
		t.Fatalf("ResolveBusAddressForOS(linux) = (%q, %v), want (%q, nil)", addr, err, PosixBusAddress)
	}

	if _, err := ResolveBusAddressForOS("linux", "http://127.0.0.1:8080"); !errors.Is(err, ErrLoopbackHTTPForbidden) {
		t.Fatalf("expected B8G016 error for HTTP override, got %v", err)
	}

	t.Setenv(EnvBusAddress, "http://localhost:8080/internal")
	if _, err := ResolveBusAddressForOS("windows", ""); !errors.Is(err, ErrLoopbackHTTPForbidden) {
		t.Fatalf("expected B8G016 error for HTTP env override, got %v", err)
	}
}

func TestNdjsonFrameRoundTrip(t *testing.T) {
	type uploadPackReq struct {
		Repo  string `json:"repo"`
		KeyID string `json:"key_id"`
	}

	reqFrame, err := NewNdjsonFrame(ChannelGitUploadPack, "gitlab-shell", uploadPackReq{
		Repo:  "awesome-os/gitlab-foss.git",
		KeyID: "key-42",
	})
	if err != nil {
		t.Fatalf("NewNdjsonFrame failed: %v", err)
	}

	authFrame, err := NewNdjsonFrame(ChannelSSHAuth, "gitlab-shell", map[string]string{
		"fingerprint": "SHA256:abc123",
	})
	if err != nil {
		t.Fatalf("NewNdjsonFrame auth failed: %v", err)
	}

	var buf bytes.Buffer
	codec := NewFrameCodec(&buf, &buf)

	if err := codec.Encode(reqFrame); err != nil {
		t.Fatalf("Encode reqFrame failed: %v", err)
	}
	if err := codec.Encode(authFrame); err != nil {
		t.Fatalf("Encode authFrame failed: %v", err)
	}

	// Verify single-line NDJSON framing (2 lines).
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d", len(lines))
	}

	gotReq, err := codec.Decode()
	if err != nil {
		t.Fatalf("Decode reqFrame failed: %v", err)
	}
	if gotReq.Magic != B8G_ABI_MAGIC_V3 {
		t.Fatalf("decoded magic = 0x%08x, want 0x%08x", gotReq.Magic, B8G_ABI_MAGIC_V3)
	}
	if gotReq.Channel != ChannelGitUploadPack || gotReq.Persona != "gitlab-shell" {
		t.Fatalf("decoded header = (%q, %q), want (%q, %q)", gotReq.Channel, gotReq.Persona, ChannelGitUploadPack, "gitlab-shell")
	}
	var decodedPayload uploadPackReq
	if err := json.Unmarshal(gotReq.Payload, &decodedPayload); err != nil {
		t.Fatalf("unmarshal payload failed: %v", err)
	}
	if decodedPayload.Repo != "awesome-os/gitlab-foss.git" || decodedPayload.KeyID != "key-42" {
		t.Fatalf("decoded payload = %+v, unexpected", decodedPayload)
	}

	gotAuth, err := codec.Decode()
	if err != nil {
		t.Fatalf("Decode authFrame failed: %v", err)
	}
	if gotAuth.Magic != B8G_ABI_MAGIC_V3 || gotAuth.Channel != ChannelSSHAuth {
		t.Fatalf("decoded auth frame = %+v, unexpected", gotAuth)
	}

	if _, err := codec.Decode(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF after reading all frames, got %v", err)
	}
}

func TestNdjsonFrameRejectsInvalidMagic(t *testing.T) {
	badFrame := &NdjsonFrame{
		Magic:   0xDEADBEEF,
		Channel: ChannelSSHAuth,
		Persona: "gitlab-shell",
		Payload: json.RawMessage(`{"ok":true}`),
	}

	var buf bytes.Buffer
	if err := EncodeNdjsonFrame(&buf, badFrame); !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("EncodeNdjsonFrame with bad magic error = %v, want ErrInvalidMagic", err)
	}

	rawBad := `{"magic":3735928559,"channel":"ssh-auth","persona":"gitlab-shell","payload":{"ok":true}}` + "\n"
	if _, err := DecodeNdjsonFrame(strings.NewReader(rawBad)); !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("DecodeNdjsonFrame with bad magic error = %v, want ErrInvalidMagic", err)
	}

	rawMissingMagic := `{"channel":"ssh-auth","payload":{}}` + "\n"
	if _, err := DecodeNdjsonFrame(strings.NewReader(rawMissingMagic)); !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("DecodeNdjsonFrame with missing magic error = %v, want ErrInvalidMagic", err)
	}
}
