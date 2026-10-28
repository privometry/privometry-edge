package content

import "fmt"

// Check runs every detector's own samples: each match sample must make the
// detector fire on every source it applies to, and no no_match sample may.
// It is the release gate for a detector pack.
func Check(p *Pack) []error {
	var errs []error
	for _, d := range p.Detectors {
		e := New([]*Pack{{Detectors: []*Compiled{d}}}, Options{})
		for _, src := range d.AppliesTo {
			for _, s := range d.Samples.Match {
				if len(e.Scan(src, s)) == 0 {
					errs = append(errs, fmt.Errorf("%s on %s: does not fire on match sample %q", d.QID, src, s))
				}
			}
			for _, s := range d.Samples.NoMatch {
				if fs := e.Scan(src, s); len(fs) > 0 {
					errs = append(errs, fmt.Errorf("%s on %s: fires on no_match sample %q (%s)", d.QID, src, s, fs[0].Excerpt))
				}
			}
		}
	}
	return errs
}
