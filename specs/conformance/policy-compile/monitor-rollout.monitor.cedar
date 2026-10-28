@id("q4-rollout:ask-package-installs")
@verdict("ask")
@layer("org")
@category("other")
permit (principal, action == Privometry::Action::"shell_exec", resource)
when { context.intent.contains("package_install") };

