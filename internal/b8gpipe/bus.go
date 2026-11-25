package b8gpipe

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"strings"
)

const (
	// B8G_ABI_MAGIC_V3 is the Awesome-OS v3 local IPC ABI magic number ("BGV3").
	B8G_ABI_MAGIC_V3 uint32 = 0x33564742

	// WindowsBusAddress is the canonical Windows named pipe for local IPC.
	WindowsBusAddress = `\\.\pipe\b8g-host-bus`

	// PosixBusAddress is the canonical Unix domain socket for local IPC on Linux/macOS.
	PosixBusAddress = "/run/b8g/host-bus.sock"

	// EnvBusAddress optionally overrides the default bus address.
	EnvBusAddress = "B8G_HOST_BUS"

	// Standard NDJSON channels for gitlab-shell SSH-to-control-plane negotiation.
	ChannelCommand       = "command"
	ChannelSSHAuth       = "ssh-auth"
	ChannelGitUploadPack = "git-upload-pack"
)

var (
	// ErrLoopbackHTTPForbidden indicates a B8G016 violation: local HTTP/loopback IPC is prohibited.
	ErrLoopbackHTTPForbidden = errors.New("B8G016: local HTTP/loopback IPC is forbidden; use named pipe or unix domain socket")

	// ErrInvalidBusAddress indicates a malformed or unsupported local IPC bus address.
	ErrInvalidBusAddress = errors.New("b8gpipe: invalid local IPC bus address")

	// ErrInvalidMagic indicates a frame whose Magic does not match B8G_ABI_MAGIC_V3.
	ErrInvalidMagic = errors.New("b8gpipe: invalid ABI magic (expected 0x33564742)")

	// ErrEmptyChannel indicates a frame missing a required channel identifier.
	ErrEmptyChannel = errors.New("b8gpipe: frame channel must not be empty")
)

// DefaultBusAddress returns the canonical Awesome-OS host bus address for the current OS.
func DefaultBusAddress() string {
	return DefaultBusAddressForOS(runtime.GOOS)
}

// DefaultBusAddressForOS returns the canonical Awesome-OS host bus address for the given GOOS.
func DefaultBusAddressForOS(goos string) string {
	if strings.EqualFold(goos, "windows") {
		return WindowsBusAddress
	}
	return PosixBusAddress
}

// ValidateBusAddress verifies that addr is a valid local pipe or Unix socket address
// and strictly rejects any HTTP or loopback TCP endpoint per B8G016.
func ValidateBusAddress(addr string) error {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return fmt.Errorf("%w: address is empty", ErrInvalidBusAddress)
	}

	lower := strings.ToLower(trimmed)

	// Strictly reject HTTP(S) / WebSocket schemes and loopback hosts (B8G016).
	if strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "ws://") ||
		strings.HasPrefix(lower, "wss://") {
		return fmt.Errorf("%w: %q", ErrLoopbackHTTPForbidden, trimmed)
	}

	if isLoopbackAddress(lower) {
		return fmt.Errorf("%w: %q", ErrLoopbackHTTPForbidden, trimmed)
	}

	// Accept Windows named pipes: \\.\pipe\<name>
	if strings.HasPrefix(trimmed, `\\.\pipe\`) && len(trimmed) > len(`\\.\pipe\`) {
		return nil
	}

	// Accept explicit unix:// socket URIs.
	if strings.HasPrefix(lower, "unix://") {
		sockPath := strings.TrimPrefix(trimmed, trimmed[:len("unix://")])
		if strings.HasPrefix(sockPath, "/") && len(sockPath) > 1 {
			return nil
		}
		return fmt.Errorf("%w: invalid unix socket URI %q", ErrInvalidBusAddress, trimmed)
	}

	// Accept POSIX absolute Unix domain socket paths.
	if strings.HasPrefix(trimmed, "/") && len(trimmed) > 1 {
		return nil
	}

	return fmt.Errorf("%w: %q", ErrInvalidBusAddress, trimmed)
}

func isLoopbackAddress(lower string) bool {
	if strings.HasPrefix(lower, "127.0.0.1") ||
		strings.HasPrefix(lower, "localhost") ||
		strings.HasPrefix(lower, "[::1]") ||
		strings.HasPrefix(lower, "::1") ||
		strings.HasPrefix(lower, "0.0.0.0") {
		return true
	}

	if strings.Contains(lower, "://") {
		if parsed, err := url.Parse(lower); err == nil {
			host := parsed.Hostname()
			if host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "0.0.0.0" {
				return true
			}
		}
	}

	return false
}

// ResolveBusAddress resolves the local IPC bus address from an explicit override,
// the B8G_HOST_BUS environment variable, or the OS-specific default.
func ResolveBusAddress(override string) (string, error) {
	return ResolveBusAddressForOS(runtime.GOOS, override)
}

// ResolveBusAddressForOS resolves and validates the local IPC bus address for a target GOOS.
func ResolveBusAddressForOS(goos, override string) (string, error) {
	candidate := strings.TrimSpace(override)
	if candidate == "" {
		candidate = strings.TrimSpace(os.Getenv(EnvBusAddress))
	}
	if candidate == "" {
		candidate = DefaultBusAddressForOS(goos)
	}
	if err := ValidateBusAddress(candidate); err != nil {
		return "", err
	}
	return candidate, nil
}

// NdjsonFrame is a single newline-delimited JSON envelope transmitted over the
// B8G host bus for gitlab-shell SSH auth and git-upload-pack negotiation.
type NdjsonFrame struct {
	Magic   uint32          `json:"magic"`
	Channel string          `json:"channel"`
	Persona string          `json:"persona,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

// NewNdjsonFrame constructs a validated NdjsonFrame stamped with B8G_ABI_MAGIC_V3.
func NewNdjsonFrame(channel, persona string, payload any) (*NdjsonFrame, error) {
	var raw json.RawMessage
	switch v := payload.(type) {
	case nil:
		raw = json.RawMessage("null")
	case json.RawMessage:
		raw = append(json.RawMessage(nil), v...)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("b8gpipe: marshal payload: %w", err)
		}
		raw = b
	}

	frame := &NdjsonFrame{
		Magic:   B8G_ABI_MAGIC_V3,
		Channel: channel,
		Persona: persona,
		Payload: raw,
	}
	if err := frame.Validate(); err != nil {
		return nil, err
	}
	return frame, nil
}

// Validate checks that the frame carries B8G_ABI_MAGIC_V3, a non-empty channel,
// and valid JSON payload bytes (if present).
func (f *NdjsonFrame) Validate() error {
	if f == nil {
		return errors.New("b8gpipe: nil frame")
	}
	if f.Magic != B8G_ABI_MAGIC_V3 {
		return fmt.Errorf("%w: got 0x%08x", ErrInvalidMagic, f.Magic)
	}
	if strings.TrimSpace(f.Channel) == "" {
		return ErrEmptyChannel
	}
	if len(f.Payload) > 0 && !json.Valid(f.Payload) {
		return errors.New("b8gpipe: invalid JSON payload")
	}
	return nil
}

// EncodeNdjsonFrame validates and writes frame as a single compact NDJSON line to w.
func EncodeNdjsonFrame(w io.Writer, frame *NdjsonFrame) error {
	if err := frame.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("b8gpipe: encode frame: %w", err)
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

// DecodeNdjsonFrame reads and validates a single NDJSON frame from r.
func DecodeNdjsonFrame(r io.Reader) (*NdjsonFrame, error) {
	return decodeNdjsonLine(bufio.NewReader(r))
}

// FrameCodec provides buffered streaming NDJSON encoding and decoding over a pipe or socket.
type FrameCodec struct {
	reader *bufio.Reader
	writer io.Writer
}

// NewFrameCodec creates a streaming FrameCodec backed by r and w.
func NewFrameCodec(r io.Reader, w io.Writer) *FrameCodec {
	var br *bufio.Reader
	if r != nil {
		br = bufio.NewReader(r)
	}
	return &FrameCodec{
		reader: br,
		writer: w,
	}
}

// Encode validates and writes a single NDJSON frame.
func (c *FrameCodec) Encode(frame *NdjsonFrame) error {
	if c == nil || c.writer == nil {
		return errors.New("b8gpipe: codec writer is nil")
	}
	return EncodeNdjsonFrame(c.writer, frame)
}

// Decode reads and validates the next NDJSON frame from the stream.
func (c *FrameCodec) Decode() (*NdjsonFrame, error) {
	if c == nil || c.reader == nil {
		return nil, errors.New("b8gpipe: codec reader is nil")
	}
	return decodeNdjsonLine(c.reader)
}

func decodeNdjsonLine(br *bufio.Reader) (*NdjsonFrame, error) {
	for {
		line, err := br.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			if errors.Is(err, io.EOF) {
				return nil, io.EOF
			}
			continue
		}

		var frame NdjsonFrame
		if uerr := json.Unmarshal(trimmed, &frame); uerr != nil {
			return nil, fmt.Errorf("b8gpipe: decode frame: %w", uerr)
		}
		if verr := frame.Validate(); verr != nil {
			return nil, verr
		}
		return &frame, nil
	}
}
