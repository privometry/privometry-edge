@id("q4-rollout:deny-uploads-to-unknown-hosts")
@verdict("deny")
@layer("org")
@category("exfiltration")
forbid (principal, action in [Privometry::Action::"shell_exec", Privometry::Action::"network_fetch"], resource)
when { context.intent.contains("network_upload") }
unless { (context.host like "*.acme.com" || context.host like "*.amazonaws.com") };

