// Package rulepacks embeds the rule packs shipped in the sensor. The test in
// this folder is the release gate every pack must pass.
package rulepacks

import "embed"

// FS holds each pack's manifest and rule files.
//
//go:embed */pack.yaml */rules/*.yaml
var FS embed.FS
