# Glossary

**Adapter:** A versioned data definition that translates one coding agent's discovery, configuration, hooks, tools, arguments, and replies into Privometry's normalized model.

**Ask:** A verdict requiring human or approved remote confirmation before an action proceeds.

**Bundle:** A signed organization-policy artifact distributed to edges and gateways, optionally carrying signed entitlements.

**Cedar:** The embedded authorization language used after Privometry compiles YAML policy into evaluator input.

**Content finding:** A redacted detector result for a secret, injection, hidden content, or safety-weakening instruction.

**Detector pack:** Versioned metadata and detectors used by the content engine.

**DSSE:** Dead Simple Signing Envelope, used to bind a payload and media type to one or more signatures.

**Edge:** The local Go binaries running on a developer endpoint.

**Entitlement:** A signed capability or limit consumed by components. It is distinct from invoices and payment-provider state.

**Fail mode:** The hook client's local decision when the daemon cannot answer before the deadline.

**Guard:** The CLI workflow that installs, removes, and checks Privometry hooks in supported coding agents.

**Hook:** An agent-provided callback that invokes `privometry-hook` before or after a tool or lifecycle event.

**Intent extraction:** Conversion of raw commands and arguments into normalized actions and policy facts.

**Locked rule:** A higher-layer rule that lower policy layers cannot weaken.

**MCP:** Model Context Protocol, used by agents to invoke external tools and data sources.

**Monitor rule:** A rule evaluated for observation without applying its would-be blocking verdict.

**Policy layer:** One source in the merge order: built-in, organization, repository, or user.

**Privacy level:** The event contract's classification of how data was redacted, hashed, or represented.

**Rule pack:** Versioned metadata, rules, and tests distributed with or to the edge.

**Session state:** Per-agent-session facts such as whether untrusted or injected content was observed.

**Spool:** A bounded local buffer for events created when the daemon or upload path is unavailable.

**Timeline:** The redacted, locally stored sequence of actions, findings, configuration changes, integrity signals, and fail-mode events.

**Trust root:** Pinned public keys that authorize role-specific signing keys and rotations.
