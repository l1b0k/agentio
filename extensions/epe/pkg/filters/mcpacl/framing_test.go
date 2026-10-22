// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package mcpacl

import (
	"context"
	"testing"
)

// MCP 2025-06-18 removed JSON-RPC batching and requires the POST body to be a
// single JSON-RPC message. A body that violates that framing — a top-level
// array, or a second document after the first — hides tool names from the ACL
// while remaining actionable by a lenient upstream parser.
//
// Inspection failures must deny under both allow and deny defaults.

// blacklistPolicy denies exec_command and allows everything else, so a
// passthrough bug is visible as ActionContinue rather than being masked by a
// deny-by-default.
func blacklistPolicy() *Config {
	return &Config{
		DefaultAction: "allow",
		Rules: []RuleEntry{
			{Method: "tools/call", ToolNames: []string{"exec_command"}, Action: "deny"},
		},
	}
}

// whitelistPolicy allows only read_file; inspection failures also deny.
func whitelistPolicy() *Config {
	return &Config{
		DefaultAction: "deny",
		Rules: []RuleEntry{
			{Method: "tools/call", ToolNames: []string{"read_file"}, Action: "allow"},
		},
	}
}

func TestFinalize_FramingViolation_FailsClosed(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{
			name: "two concatenated documents",
			body: []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}` +
				`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"exec_command"},"id":2}`),
		},
		{
			name: "two newline separated documents",
			body: []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}` + "\n" +
				`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"exec_command"},"id":2}`),
		},
		{
			name: "top level array",
			body: []byte(`[{"jsonrpc":"2.0","method":"tools/call","params":{"name":"exec_command"},"id":1}]`),
		},
		{
			name: "trailing garbage after valid document",
			body: []byte(`{"jsonrpc":"2.0","method":"initialize","id":1} trailing`),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name+"/blacklist denies it", func(t *testing.T) {
			p := newLegacyPlugin()
			rctx := makeRctx("application/json")
			rctx.RequestBody = tc.body

			result, err := p.Finalize(context.Background(), rctx, nil, makeRule(blacklistPolicy()))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Action != legacyImmediate {
				t.Errorf("framing violation under defaultAction=allow must be denied, got %v", result.Action)
			}
		})

		t.Run(tc.name+"/whitelist denies it", func(t *testing.T) {
			p := newLegacyPlugin()
			rctx := makeRctx("application/json")
			rctx.RequestBody = tc.body

			result, err := p.Finalize(context.Background(), rctx, nil, makeRule(whitelistPolicy()))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Action != legacyImmediate {
				t.Errorf("framing violation under defaultAction=deny must be denied, got %v", result.Action)
			}
		})
	}
}

// The framing rule is asserted at readBody, the level that decides, rather than
// against a helper: a batch is refused by the explicit isBatchBody check, and
// every other violation is refused because json.Unmarshal rejects trailing
// content after the first document. Both land on statusUnreadable, so this test
// is what keeps that guarantee from silently disappearing — notably if Unmarshal
// were ever swapped for a json.Decoder, which does not reject what follows.
func TestReadBody_Framing(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want bodyStatus
	}{
		{"top level array", []byte(`[{"jsonrpc":"2.0","method":"tools/call","params":{"name":"a"}}]`), statusUnreadable},
		{"top level array truncated", []byte(`[{"method":"tools/`), statusUnreadable},
		{"second document begins", []byte(`{"method":"tools/call","params":{"name":"a"}}{`), statusUnreadable},
		{"two complete documents", []byte(`{"method":"tools/call","params":{"name":"a"}}` +
			`{"method":"tools/call","params":{"name":"b"}}`), statusUnreadable},
		{"trailing garbage", []byte(`{"jsonrpc":"2.0","method":"initialize","id":1} trailing`), statusUnreadable},
		{"truncated single document", []byte(`{"method":"tools/`), statusUnreadable},
		{"complete single document", []byte(`{"method":"tools/call","params":{"name":"a"}}`), statusMessage},
		{"trailing whitespace is legal", []byte(`{"method":"tools/call","params":{"name":"a"}}` + " \r\n\t"), statusMessage},
		{"empty", nil, statusAbsent},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := readBody(nil, tc.body).status; got != tc.want {
				t.Errorf("readBody(%q).status = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// Compliant single-document bodies must keep flowing. Insignificant trailing
// whitespace is legal JSON framing and must not be mistaken for a second
// document.
func TestFinalize_CompliantFraming_NotTreatedAsViolation(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want legacyAction
	}{
		{
			name: "allowed tool",
			body: []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}`),
			want: legacyContinue,
		},
		{
			name: "denied tool still denied",
			body: []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"exec_command"},"id":1}`),
			want: legacyImmediate,
		},
		{
			name: "trailing newline",
			body: []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}` + "\n"),
			want: legacyContinue,
		},
		{
			name: "leading and trailing whitespace",
			body: []byte("  \t" + `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"},"id":1}` + " \r\n"),
			want: legacyContinue,
		},
		{
			name: "empty body passes through",
			body: nil,
			want: legacyContinue,
		},
		{
			name: "unparseable body denied",
			body: []byte(`not json at all`),
			want: legacyImmediate,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newLegacyPlugin()
			rctx := makeRctx("application/json")
			rctx.RequestBody = tc.body

			result, err := p.Finalize(context.Background(), rctx, nil, makeRule(blacklistPolicy()))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Action != tc.want {
				t.Errorf("got %v, want %v", result.Action, tc.want)
			}
		})
	}
}

// The incremental parser must not depend on JSON member order. Object member
// order is semantically meaningless and attacker-controlled, and a Go client
// that builds params as map[string]any gets "arguments" before "name" from
// encoding/json's key sorting. Returning a tool name without the method makes
// the pair undecidable for every prefix, including the complete body.
func TestStreamingParsePartial_FieldOrderIndependent(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantMethod   string
		wantToolName string
	}{
		{
			name:         "method then params, name then arguments",
			body:         `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"evil","arguments":{"a":"b"}}}`,
			wantMethod:   "tools/call",
			wantToolName: "evil",
		},
		{
			name:         "method then params, arguments then name",
			body:         `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"a":"b"},"name":"evil"}}`,
			wantMethod:   "tools/call",
			wantToolName: "evil",
		},
		{
			name:         "params then method, name then arguments",
			body:         `{"jsonrpc":"2.0","id":1,"params":{"name":"evil","arguments":{"a":"b"}},"method":"tools/call"}`,
			wantMethod:   "tools/call",
			wantToolName: "evil",
		},
		{
			name:         "params then method, arguments then name",
			body:         `{"jsonrpc":"2.0","id":1,"params":{"arguments":{"a":"b"},"name":"evil"},"method":"tools/call"}`,
			wantMethod:   "tools/call",
			wantToolName: "evil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			method, toolName := streamingParsePartial([]byte(tc.body))
			if method != tc.wantMethod {
				t.Errorf("method = %q, want %q", method, tc.wantMethod)
			}
			if toolName != tc.wantToolName {
				t.Errorf("toolName = %q, want %q", toolName, tc.wantToolName)
			}
		})
	}
}
