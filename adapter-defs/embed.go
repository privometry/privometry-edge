// Package adapterdefs embeds the adapter definitions shipped in the sensor
// binary. A newer signed adapter set installed with privometry definitions
// replaces them at run time; see internal/definitions.
package adapterdefs

import "embed"

// SetVersion is the adapter set version these definitions form. Bump it
// whenever a definition here changes, so a signed set built from the old
// definitions can never replace the new ones; internal/definitions pins the
// content of each version in a test.
const SetVersion = 6

// FS holds every *.yaml definition in this folder.
//
//go:embed *.yaml
var FS embed.FS
