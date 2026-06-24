# Server runtime certificates

These files are needed at runtime when the Go server starts.

| File | Committed? | How to get it |
|------|-----------|---------------|
| `server.pem` | ✅ Yes | `certs/init-ca.sh` → copy here |
| `server-key.pem` | ❌ Never | `certs/init-ca.sh` → copy here (keep secret) |
| `intermediate-ca.pem` | ✅ Yes | `certs/init-ca.sh` → copy here |
| `crl.pem` | ✅ Yes | `certs/init-ca.sh` → copy here (regenerate on revocation) |

Run `certs/init-ca.sh` once from the repo root, then copy the output here.
After each device cert revocation, regenerate `crl.pem` and redeploy.
