// Expected compiler output for examples/valid/content-scanning.yaml loaded as
// the organization layer. The content facts come from the Go detectors.

@id("acme-content:no-secrets-to-network")
@verdict("deny")
@layer("org")
@category("exfiltration")
forbid (principal, action in [Privometry::Action::"network_fetch", Privometry::Action::"mcp_call"], resource)
when { !context.secret_detected.isEmpty() };

@id("acme-content:ask-cloud-keys-in-code")
@verdict("ask")
@layer("org")
@category("secrets")
permit (principal, action == Privometry::Action::"file_write", resource)
when {
  context.secret_detected.containsAny(["aws_access_key", "gcp_service_account_key"]) &&
  context.target_class == "code"
};

@id("acme-content:guard-memory-files")
@verdict("ask")
@layer("org")
@category("other")
permit (principal, action == Privometry::Action::"file_write", resource)
when { context.target_class == "memory_file" };

@id("acme-content:block-memory-writes-after-injection")
@verdict("deny")
@layer("org")
@category("other")
forbid (principal, action == Privometry::Action::"file_write", resource)
when { context.injection_seen && context.target_class == "memory_file" };

@id("acme-content:ask-hidden-instructions")
@verdict("ask")
@layer("org")
@category("other")
permit (principal, action in [Privometry::Action::"file_write", Privometry::Action::"mcp_call"], resource)
when { ["medium", "high"].contains(context.injection_detected) && context.hidden_content };
