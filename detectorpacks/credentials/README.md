# privometry/credentials detector pack

Finds credentials in what agents send and write and in files at rest: provider tokens and keys, private keys, JWTs, passwords in connection strings, bearer tokens, and random values assigned to secret-named variables.

Each detector names its `secret_type`, which policy rules match with `secret_detected` (for example `secret_detected: [aws_access_key]`, or `any`). Findings carry a masked excerpt and a salted fingerprint, never the value.

Samples are fake but correctly formed, and split with `{{}}` so secret scanners do not flag them. Run the samples with `go test ./detectorpacks/`.
