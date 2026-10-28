@id("platform-guardrails:block-blocked-mcp")
@verdict("deny")
@layer("org")
@category("unapproved_mcp")
forbid (principal, action == Privometry::Action::"mcp_call", resource)
when { context.catalog_status == "blocked" };

@id("platform-guardrails:ask-unapproved-mcp")
@verdict("ask")
@layer("org")
@category("unapproved_mcp")
permit (principal, action == Privometry::Action::"mcp_call", resource)
when { ["unapproved", "unknown"].contains(context.catalog_status) };

@id("platform-guardrails:no-db-writes-from-mcp")
@verdict("deny")
@layer("org")
@category("catastrophic")
forbid (principal, action == Privometry::Action::"mcp_call", resource)
when { (context.mcp_server like "postgres*" || context.mcp_server like "*-db") && (context.mcp_tool == "execute_sql" || context.mcp_tool like "*drop*" || context.mcp_tool like "*truncate*") };

@id("platform-guardrails:payments-ask-on-high-risk")
@verdict("ask")
@layer("org")
@category("other")
permit (principal, action, resource)
when { context.risk >= 3 && ["cursor", "codex_cli"].contains(principal.product) && (resource is Privometry::Repo && resource.remote like "github.com/acme/payments-*") };

@id("platform-guardrails:no-force-flags-in-git")
@verdict("deny")
@layer("org")
@category("catastrophic")
forbid (principal, action == Privometry::Action::"shell_exec", resource)
when { context.intent.contains("force_push") && context.program == "git" && context.flags.containsAny(["--force", "-f", "--force-with-lease"]) };

@id("platform-guardrails:secrets-outside-repo")
@verdict("deny")
@layer("org")
@category("secrets")
forbid (principal, action in [Privometry::Action::"file_read", Privometry::Action::"shell_exec"], resource)
when { context.intent.contains("secret_read") && ["home", "secret_store"].contains(context.path_class) };

