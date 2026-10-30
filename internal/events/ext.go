package events

// FingerprintKeyExt is the local-only ext field naming the key of a content
// finding's fingerprint: the organization hash key's ID when enrolled. A
// connector drops it before upload.
const FingerprintKeyExt = "x_privometry_fingerprint_key"
