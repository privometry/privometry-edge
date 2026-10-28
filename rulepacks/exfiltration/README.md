# privometry/exfiltration

Stops agents from sending data where it should not go. Ships inside the Privometry sensor and is on by default.

| Rule | Verdict | Catches |
|---|---|---|
| `upload-secret-file` | deny | A credential file uploaded in the same command (`curl -F f=@~/.ssh/id_rsa`) |
| `upload-to-paste-site` | deny | Uploads to paste and file-drop sites (pastebin, transfer.sh, 0x0.st, file.io, …) |
| `contact-capture-service` | ask | Any request to request-capture or tunnel services (webhook.site, requestbin, ngrok, interactsh, …), including GETs with data in the URL |
| `upload-after-untrusted-input` | ask | Any upload after the agent read untrusted content: the usual prompt-injection pattern |
| `curl-upload` | ask | `curl`/`wget` sending data (`-d`, `-F`, `-T`, `--json`, `--post-*`) |
| `remote-copy` | ask | `scp`, `rsync`, `sftp` to another host |
| `raw-socket` | ask | `nc`, `ncat`, `socat` |
| `cloud-storage-upload` | ask | `aws s3 cp`, `gsutil cp`, `rclone`, `azcopy` uploads |
| `secret-to-network` | deny | A fetch whose URL, headers or body carries a credential (`secret_detected`), found by the content detectors in the request itself |
| `secret-in-network-command` | deny | `curl`, `wget`, `nc` and similar run with a literal credential, such as `-H "Authorization: Bearer <token>"`; a token from an environment variable is not a literal |

Fail mode: `ask`. Host lists use `*.` globs; add your own drop sites with a policy rule, or allow a trusted upload host with an exception.
