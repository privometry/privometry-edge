// Expected compiler output for examples/valid/acme-default.yaml loaded as the
// organization layer. Only the file's own rules appear here; extended packs,
// overrides and exceptions are applied when the bundle is assembled.

@id("acme-default:no-terraform-destroy")
@verdict("deny")
@layer("org")
@category("catastrophic")
forbid (principal, action == Privometry::Action::"shell_exec", resource)
when {
  context.program == "terraform" &&
  (context.subcommand == "destroy" || context.subcommand like "destroy *")
};

@id("acme-default:allow-tests")
@verdict("allow")
@layer("org")
@category("other")
permit (principal, action == Privometry::Action::"shell_exec", resource)
when {
  ["npm", "pnpm", "go", "mvn", "gradle"].contains(context.program) &&
  (context.subcommand == "test" || context.subcommand like "test *" ||
   context.subcommand == "run test" || context.subcommand like "run test *")
};

@id("acme-default:ask-untrusted-network")
@verdict("ask")
@layer("org")
@category("other")
permit (principal, action == Privometry::Action::"network_fetch", resource)
when { context.untrusted_input_seen }
unless { context.host like "*.github.com" || context.host == "registry.npmjs.org" };
