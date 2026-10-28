# Community rule packs

Rule packs published by others are not shipped in the sensor. A publisher
signs a pack with their own key (`privometry packs keygen`, then
`privometry packs sign`), people trust that key with `privometry trust add`,
and install the signed pack with `privometry packs install`. A policy then
opts in with `extends: [<publisher>/<name>@<range>]`. See
`docs/community-packs.md`.

`example-helm-guard/` is the template the tests sign; the release gate in
`../rulepacks_test.go` runs its tests too.
