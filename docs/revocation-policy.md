# SignMedia Revocation & Historical Validation Policy

This document defines status states and historical evaluation rules for certificates, signer keys, and asset evidence.

## 1. Status States
- **Good**: Evidence is valid and explicitly unrevoked.
- **Revoked**: Key, certificate, or asset identifier is present on a verified revocation list.
- **Unknown**: Revocation status cannot be confirmed due to missing status responses.
- **Stale**: Status response has passed its `nextUpdate` time.
- **Unavailable**: Offline or network failure prevented status check.

## 2. Historical Evaluation
If a valid RFC 3161 timestamp proves a signature existed at time $T_{\text{sig}}$, and a revocation occurred at $T_{\text{revoc}}$:
- If $T_{\text{sig}} < T_{\text{revoc}}$, the historical signature remains valid under historical policy.
- If $T_{\text{sig}} \ge T_{\text{revoc}}$, the signature is invalid.
