// Package timelineweb holds the browser timeline's static files, which
// privometry timeline --web serves from the binary.
package timelineweb

import "embed"

// Files is index.html and the files it loads, including the fonts in
// fonts/ (SIL Open Font License; see fonts/OFL.txt).
//
//go:embed index.html app.js style.css fonts
var Files embed.FS
