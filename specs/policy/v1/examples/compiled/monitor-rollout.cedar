// Enforce set for examples/valid/monitor-rollout.yaml (repo layer): the one
// rule that sets mode: enforce over the file's monitor default.

@id("q4-rollout:deny-uploads-to-unknown-hosts")
@verdict("deny")
@layer("repo")
@category("exfiltration")
forbid (
  principal,
  action in [Privometry::Action::"shell_exec", Privometry::Action::"network_fetch"],
  resource
)
when { context.intent.contains("network_upload") }
unless { context.host like "*.acme.com" || context.host like "*.amazonaws.com" };
