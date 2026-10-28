// Monitor set for examples/valid/monitor-rollout.yaml. Evaluated after the
// enforce set; its result is recorded as decision.would_verdict only.

@id("q4-rollout:ask-package-installs")
@verdict("ask")
@layer("repo")
@category("other")
permit (principal, action == Privometry::Action::"shell_exec", resource)
when { context.intent.contains("package_install") };
