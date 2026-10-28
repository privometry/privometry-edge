// Package detectorpacks embeds the content detector packs shipped in the
// sensor. The test in this folder is the release gate every pack must pass.
// A newer signed detector pack set installed with privometry definitions
// replaces them at run time; see internal/definitions.
package detectorpacks

import "embed"

// SetVersion is the detector pack set version these packs form. Bump it
// whenever a pack here changes, so a signed set built from the old packs can
// never replace the new ones; internal/definitions pins the content of each
// version in a test.
const SetVersion = 3

// FS holds each pack's manifest and detector files.
//
//go:embed */pack.yaml */detectors/*.yaml
var FS embed.FS
