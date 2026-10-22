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

// Package mcpacl enforces MCP tool ACLs. Header-derived denials can short-
// circuit, but every possible allow requires body inspection.
package mcpacl

import (
	"context"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// FilterName is the registry name used for attribution.
const FilterName = "mcpacl"

// actionAllow is the only value that admits a governed call. Every other
// value — an explicit deny, a differently-cased or misspelled verb, an
// un-defaulted empty string — denies. Spelling the permissive value exactly,
// rather than the restrictive one, is what keeps an unrecognized action from
// silently disabling the rule it was written for.
const (
	actionAllow       = "allow"
	actionDeny        = "deny"
	actionPassthrough = "passthrough"
)

// defaultDenyStatus is used when the policy does not configure a deny
// response status.
const defaultDenyStatus = 403

// Config is the filter's decoded form of an mcpacl policy payload.
type Config struct {
	DefaultAction            string
	UnsupportedVersionAction string
	// DenyStatus 0 means the default 403.
	DenyStatus int32
	DenyBody   string
	Rules      []RuleEntry
}

// RuleEntry is one policy rule.
type RuleEntry struct {
	Method    string
	ToolNames []string
	Action    string
}

// evaluate walks the policy rules for a decision; unmatched falls back to
// DefaultAction. The returned value is only ever honoured as an allow when it
// is exactly actionAllow — see the call site.
func evaluate(cfg Config, method, toolName string) string {
	for _, rule := range cfg.Rules {
		if rule.Method != method {
			continue
		}
		if len(rule.ToolNames) == 0 {
			return rule.Action
		}
		if toolName == "" {
			continue
		}
		if contains(rule.ToolNames, toolName) {
			return rule.Action
		}
	}
	return cfg.DefaultAction
}

func contains(names []string, target string) bool {
	for _, n := range names {
		if n == target {
			return true
		}
	}
	return false
}

func denyReply(cfg Config) filter.Reply {
	status := int(cfg.DenyStatus)
	if status == 0 {
		status = defaultDenyStatus
	}
	var body []byte
	if cfg.DenyBody != "" {
		body = []byte(cfg.DenyBody)
	}
	return filter.Reply{Status: status, Body: body}
}

// Filter evaluates one rule's MCP tool policy.
type Filter struct {
	filter.PassThrough
	rule filter.RuleConfig[Config]
}

func New(rule filter.RuleConfig[Config]) filter.Filter { return &Filter{rule: rule} }

// OnRequestHeaders can deny governed calls early. Every other request needs
// body inspection, including non-governed headers that could hide a tool call.
func (f *Filter) OnRequestHeaders(ctx context.Context, st *filter.Stream) (filter.Action, error) {
	version := st.Request.Headers[mcpProtocolVersionHeader]

	// Routing headers can establish an early deny, but cannot establish an
	// allow without inspecting what the upstream will execute.
	if version == gaMCPVersion {
		method := st.Request.Headers[mcpMethodHeader]
		if method != "" {
			if !governedMethods[method] {
				return filter.NeedBody(), nil
			}
			// Governed method (tools/call): evaluate from headers. A deny is
			// safe to make immediately — deny is the safe-fail direction, and
			// a client sending contradictory headers/body is suspicious. An
			// allow still needs the body to verify the header-derived tool
			// name matches the JSON-RPC payload.
			toolName := st.Request.Headers[mcpNameHeader]
			if toolName != "" {
				// Decode Base64 sentinel encoding (MCP 2026-07-28 SEP-2243)
				// for non-ASCII tool names before evaluation.
				if decoded, ok := decodeMcpHeaderValue(toolName); ok {
					toolName = decoded
				} else {
					// Invalid encoding: cannot evaluate from header, fall back to body.
					return filter.NeedBody(), nil
				}
				rc := f.rule
				if decision := evaluate(rc.Cfg, method, toolName); decision != actionAllow {
					log.FromContext(ctx).Info("MCP tool denied by header fast-path",
						"rule", rc.ID.Name, "method", method, "toolName", toolName,
						"decision", decision, "pod", st.Peer.Pod.String())
					return filter.Stop(denyReply(rc.Cfg)), nil
				}
				// Allow: fall through to NeedBody for header/body verification.
			}
		}
	}

	// Pre-2026-07-28, absent/incomplete GA headers, or allow pending
	// body verification: method is only knowable from the JSON-RPC body.
	return filter.NeedBody(), nil
}

// OnRequestBody applies the rule's policy to the single JSON-RPC message
// carried in the body; only an exact allow admits a governed call.
func (f *Filter) OnRequestBody(ctx context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	read := readBody(st.Request.Headers, body.Bytes)

	// Preserve the policy default for normalization and envelope type errors.
	// Only JSON syntax and framing failures are unconditionally rejected.
	if read.status == statusNormalizationFailed || read.status == statusUnattributed {
		if f.rule.Cfg.DefaultAction == actionAllow {
			return filter.Continue(), nil
		}
		return filter.Stop(denyReply(f.rule.Cfg)), nil
	}

	// Invalid JSON is independent of the business defaultAction.
	if read.status == statusUnreadable {
		return filter.Stop(denyReply(f.rule.Cfg)), nil
	}

	// Only tool invocations are governed; a body with no message at all, and
	// any other method (lifecycle, tools/list, resources/*, prompts/*,
	// tasks/*, ...) passes.
	if read.status == statusAbsent || !governedMethods[read.method] {
		return filter.Continue(), nil
	}
	method, toolName := read.method, read.tool

	version := st.Request.Headers[mcpProtocolVersionHeader]
	rc := f.rule
	cfg := rc.Cfg
	// A tool call MUST come from a supported protocol version unless
	// the policy opts out via unsupportedVersionAction=passthrough.
	if !supportedMCPVersions[version] {
		if cfg.UnsupportedVersionAction == actionPassthrough {
			log.FromContext(ctx).Info("MCP tool call with unsupported/absent protocol version, passing through per policy",
				"rule", rc.ID.Name, "version", version, "pod", st.Peer.Pod.String())
			return filter.Continue(), nil
		}
		log.FromContext(ctx).Info("MCP tool call with unsupported/absent protocol version, denying",
			"rule", rc.ID.Name, "version", version, "pod", st.Peer.Pod.String())
		return filter.Stop(denyReply(cfg)), nil
	}

	// The body is authoritative even when routing headers disagree. Always
	// evaluate it rather than treating matching headers as a cached allow.
	if !read.hasTool {
		// Leave parameter validation to the upstream server, preserving the
		// existing policy default when no tool name can be attributed.
		if cfg.DefaultAction == actionAllow {
			return filter.Continue(), nil
		}
		return filter.Stop(denyReply(cfg)), nil
	}

	if decision := evaluate(cfg, method, toolName); decision != actionAllow {
		log.FromContext(ctx).Info("MCP tool denied by policy",
			"rule", rc.ID.Name, "method", method, "toolName", toolName,
			"decision", decision, "pod", st.Peer.Pod.String())
		return filter.Stop(denyReply(cfg)), nil
	}
	return filter.Continue(), nil
}

// Descriptor declares mcpacl's phases and failure policy.
func Descriptor() filter.Descriptor[Config] {
	return filter.Descriptor[Config]{
		Name:    FilterName,
		Phases:  filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		OnError: filter.Always[Config](filter.FailClosed),
		New:     New,
	}
}
