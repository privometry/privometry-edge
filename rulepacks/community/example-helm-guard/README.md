# example/helm-guard

An example community rule pack, used by the tests and as a template. It is not
shipped in the sensor.

| Rule | Verdict | When |
|---|---|---|
| `helm-uninstall` | ask | `helm uninstall` or `helm delete` |
| `kubectl-drain` | ask | `kubectl drain` or `kubectl cordon` |

Use it from a policy once it is installed:

```yaml
extends: [example/helm-guard@^1]
```
