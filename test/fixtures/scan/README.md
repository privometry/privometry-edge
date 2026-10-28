# Scan fixture

A fake machine for scanner tests: `root/` stands in for `/`, with a home at
`root/home/dev`, Linux managed settings in `root/etc`, and a repo at
`root/home/dev/work/api`. Every posture check fires at least once.

The secrets here are fake. `AKIAIOSFODNN7EXAMPLE` is AWS's documented example
key; the others are made-up literals. Tests assert none of them reach any report.
