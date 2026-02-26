# Fiber Framework Security Audit Report

**Date:** 2026-02-26  
**Version Audited:** v3.1.0 (Go 1.25.0, fasthttp v1.69.0)  
**Scope:** Full codebase security review

---

## Executive Summary

This security audit examined the Fiber web framework codebase for high-risk
vulnerabilities. After thorough analysis, the framework demonstrates strong
security fundamentals. Most common web framework vulnerabilities (CRLF
injection, path traversal, XML bomb, JSON depth attacks) are properly mitigated
by the framework or underlying Go standard library.

The audit identified several findings categorized by severity. No critical
0-day vulnerabilities were found that would allow remote code execution or
direct data exfiltration in default configurations. The findings primarily
relate to defense-in-depth improvements and secure-by-default configuration
recommendations.

---

## Findings

### Finding 1: CSRF Middleware `validateSecFetchSite` Does Not Reject Cross-Site Requests

**Severity:** Medium  
**File:** `middleware/csrf/csrf.go` lines 326-339  
**Status:** Design Issue — differs from OWASP Fetch Metadata recommendation

#### Description

The `validateSecFetchSite` function is documented as rejecting cross-site
requests earlier when the `Sec-Fetch-Site` header is available (line 133
comment). However, the implementation only validates the header format — it
accepts all valid values including `cross-site`.

```go
// Line 133: "Evaluate Sec-Fetch-Site to reject cross-site requests earlier when available."
// Line 326-339:
func validateSecFetchSite(c fiber.Ctx) error {
    secFetchSite := utils.Trim(c.Get(fiber.HeaderSecFetchSite), ' ')
    if secFetchSite == "" {
        return nil
    }
    switch utilsstrings.ToLower(secFetchSite) {
    case "same-origin", "none", "cross-site", "same-site":
        return nil  // ← Accepts "cross-site" without rejection
    default:
        return ErrFetchSiteInvalid
    }
}
```

The OWASP Fetch Metadata Request Headers guide recommends rejecting requests
with `Sec-Fetch-Site: cross-site` for state-changing operations as
defense-in-depth.

#### Impact

The actual CSRF protection is still provided by the Origin/Referer header check
and CSRF token validation that follow this function. The system is NOT
vulnerable to CSRF attacks because these subsequent checks are properly
implemented. However, the `Sec-Fetch-Site` check does not provide the
defense-in-depth layer that the comment and OWASP guidelines suggest.

#### Verification

```go
// A POST request with Sec-Fetch-Site: cross-site passes this check
// but is still blocked by the Origin check (if origin doesn't match)
// and the CSRF token check.

// Test exists at csrf_test.go line 908-913:
// "cross-site with mismatched origin blocked" → 403 Forbidden (correct)
```

#### Recommendation

No immediate action required — the CSRF protection works correctly through
token validation and origin checking. Consider updating the comment at line 133
to accurately describe the function's behavior, or enhance the function to
reject `cross-site` requests following OWASP guidance.

---

### Finding 2: Session Cookies Do Not Set `HttpOnly` by Default

**Severity:** Low  
**File:** `middleware/session/config.go` line 81  
**Status:** Configuration Default — expected framework behavior

#### Description

The session middleware does not enable the `HttpOnly` cookie attribute by
default. This means session cookies are accessible via JavaScript, which could
allow session theft through XSS attacks.

```go
// middleware/session/config.go line 81:
CookieHTTPOnly bool // Default: false

// middleware/session/session.go line 490:
fcookie.SetHTTPOnly(s.config.CookieHTTPOnly)
```

#### Impact

If an application is vulnerable to XSS, an attacker could steal session cookies
using `document.cookie`. The `HttpOnly` flag prevents JavaScript from accessing
cookies, mitigating this attack vector.

#### Verification

```go
// Default session configuration:
store := session.New()
// Cookie is set WITHOUT HttpOnly:
// Set-Cookie: session_id=abc123; Path=/; SameSite=Lax
// (no HttpOnly flag)
```

#### Recommendation

Consider enabling `HttpOnly` by default. Developers who need JavaScript access
to session cookies can explicitly disable it. Most session management best
practices recommend `HttpOnly` as the default.

---

### Finding 3: Session Cookies Do Not Set `Secure` Flag by Default

**Severity:** Low  
**File:** `middleware/session/config.go` line 76  
**Status:** Configuration Default — expected framework behavior

#### Description

The session middleware does not enable the `Secure` cookie attribute by default
(except when `SameSite=None` is used). This means session cookies can be
transmitted over unencrypted HTTP connections.

```go
// middleware/session/config.go line 76:
CookieSecure bool // Default: false

// middleware/session/session.go lines 484-488:
if fcookie.SameSite() == fasthttp.CookieSameSiteNoneMode {
    fcookie.SetSecure(true)  // Forced for SameSite=None
} else {
    fcookie.SetSecure(s.config.CookieSecure)  // Default: false
}
```

#### Impact

Over HTTP, session cookies are transmitted in cleartext and can be intercepted
via man-in-the-middle attacks on the network.

#### Verification

```go
// Session cookie over HTTP:
// Set-Cookie: session_id=abc123; Path=/; SameSite=Lax
// (no Secure flag — cookie sent over HTTP)
```

#### Recommendation

Document that `Secure: true` should be set for production HTTPS deployments.
Consider auto-detecting HTTPS and enabling the `Secure` flag when TLS is
configured.

---

### Finding 4: Helmet Middleware Does Not Set HSTS or CSP by Default

**Severity:** Low  
**File:** `middleware/helmet/config.go` lines 28, 67-76  
**Status:** Configuration Default — expected framework behavior

#### Description

The helmet middleware does not set `Content-Security-Policy` or
`Strict-Transport-Security` (HSTS) headers by default. These are critical
headers for preventing XSS and HTTPS downgrade attacks.

```go
// middleware/helmet/config.go:
// ContentSecurityPolicy defaults to "" (line 28)
ContentSecurityPolicy string

// HSTSMaxAge defaults to 0 (line 68)
HSTSMaxAge int
```

#### Impact

Without CSP, applications are more vulnerable to XSS attacks. Without HSTS,
applications are vulnerable to HTTPS downgrade attacks where an attacker forces
the browser to use HTTP instead of HTTPS.

#### Verification

```go
app.Use(helmet.New())
// Response headers do NOT include:
// Content-Security-Policy: ...
// Strict-Transport-Security: ...
```

#### Recommendation

Document that HSTS and CSP should be configured for production deployments.
Consider adding a "production mode" preset that enables these headers with
sensible defaults.

---

### Finding 5: Rate Limiter IP Spoofing When ProxyHeader Is Configured

**Severity:** Medium  
**File:** `req.go` lines 588-642, `middleware/limiter/config.go` lines 93-95  
**Status:** Configuration-Dependent — requires explicit misconfiguration

#### Description

The rate limiter middleware uses `c.IP()` by default to identify clients. When
`ProxyHeader` is configured (e.g., `X-Forwarded-For`) but `EnableIPValidation`
is disabled (default), the function returns the raw header value without any
validation. An attacker can spoof different IP addresses per request to bypass
rate limits.

```go
// req.go lines 639-641:
// default behavior if IP validation is not enabled is just to return whatever value is
// in the proxy header. Even if it is empty or invalid
return r.Get(app.config.ProxyHeader)
```

#### Impact

When an application is configured with `ProxyHeader` but without
`EnableIPValidation`, attackers can bypass rate limits by sending different
`X-Forwarded-For` values with each request.

#### Verification (POC)

```bash
# Application configured with ProxyHeader: "X-Forwarded-For"
# Rate limit: 5 requests per minute

# Attacker sends requests with different spoofed IPs:
for i in $(seq 1 100); do
  curl -H "X-Forwarded-For: 10.0.0.$i" http://target/api/endpoint
done
# Each IP gets its own rate limit bucket → bypass achieved
```

#### Recommendation

This is documented behavior (see comment at `req.go` line 639-641 and
`req.go` line 511). The documentation already warns about this. Ensure
`EnableIPValidation: true` is set when using `ProxyHeader`. Consider adding a
startup warning when `ProxyHeader` is set without `EnableIPValidation`.

---

## Verified Non-Vulnerabilities

The following common attack vectors were thoroughly tested and confirmed to be
properly mitigated:

### CRLF / HTTP Response Splitting — NOT VULNERABLE ✅

**Verified at:** `vendor/github.com/valyala/fasthttp` v1.69.0, `header.go`
lines 3267-3271, 3310-3330

fasthttp's `initHeaderKV()` calls `removeNewLines()` on all header values,
replacing `\r` and `\n` with spaces. This prevents HTTP response splitting
through all Fiber header-setting methods (`Set`, `setCanonical`, `Location`,
`Redirect.To`).

```go
// fasthttp header.go:
func initHeaderKV(bufK, bufV []byte, key, value string, ...) ([]byte, []byte) {
    bufV = removeNewLines(bufV) // Strips \r and \n
    return bufK, bufV
}
```

### XML Bomb (Billion Laughs) / XXE — NOT VULNERABLE ✅

**Verified with:** Go 1.25.0 `encoding/xml`

Go's `xml.Unmarshal` does NOT process custom DTD entity definitions. It only
supports the five predefined XML entities (`&amp;`, `&lt;`, `&gt;`, `&apos;`,
`&quot;`). Custom entities like those used in billion laughs attacks produce
`XML syntax error: invalid character entity`.

```go
// Verification:
xml.Unmarshal([]byte(`<!DOCTYPE foo [<!ENTITY xxe "test">]><User>&xxe;</User>`), &user)
// Result: "XML syntax error on line 5: invalid character entity &xxe;"
```

### JSON Depth Attack — NOT VULNERABLE ✅

**Verified with:** Go 1.25.0 `encoding/json`

Go's `json.Unmarshal` enforces a built-in nesting depth limit of 10,000 levels.
Deeper nesting produces `invalid character '[' exceeded max depth`.

```go
// Verification:
// depth=10000  → Success
// depth=10001  → Error: exceeded max depth
```

### Path Traversal in Static Middleware — NOT VULNERABLE ✅

**Verified at:** `middleware/static/static.go` lines 25-115

The `sanitizePath()` function provides comprehensive defense-in-depth:

1. Backslash normalization (line 32-43)
2. Recursive URL decoding to handle double/triple encoding (lines 45-55)
3. Post-decode backslash rejection (lines 57-59)
4. Null byte rejection (lines 61-64)
5. `path.Clean()` normalization (line 71)
6. Explicit `..` component detection (lines 74-78)
7. Windows drive/UNC path rejection (lines 80-97)
8. Go `fs.ValidPath()` validation (lines 99-108)

Test coverage includes 60+ attack vectors (static_test.go lines 925-1051).

### Content-Disposition Header Injection — NOT VULNERABLE ✅

**Verified at:** `res.go` lines 182-196

The `sanitizeFilename()` function removes all Unicode control characters
(including `\r`, `\n`, `\t`, `\0`) from filenames using `unicode.IsControl()`.
Go's `unicode.IsControl()` returns `true` for CR (U+000D) and LF (U+000A),
contrary to some claims.

```go
// Verification:
unicode.IsControl('\r') // true
unicode.IsControl('\n') // true
```

### CORS Origin Validation — NOT VULNERABLE ✅

**Verified at:** `middleware/cors/cors.go`, `middleware/cors/utils.go`

The CORS middleware properly validates origins:

- Rejects wildcard `*` with credentials (panics at initialization)
- Validates origin serialization format
- Rejects null origins (case-sensitive)
- Proper subdomain wildcard validation with DNS label checks

### CSRF Token Validation — NOT VULNERABLE ✅

**Verified at:** `middleware/csrf/csrf.go` lines 156-196

CSRF token validation is properly implemented:

- Constant-time comparison using `subtle.ConstantTimeCompare()` (helpers.go
  line 22)
- Double submit cookie validation (line 174)
- Storage-backed token verification (line 178)
- Single-use token support (line 189)

### BasicAuth Timing Attacks — NOT VULNERABLE ✅

**Verified at:** `middleware/basicauth/config.go` lines 162-202

All password comparison methods use constant-time operations:

- bcrypt: inherently constant-time
- SHA-256/SHA-512: `subtle.ConstantTimeCompare()`

---

## Architecture Security Notes

### Open Redirect in Redirect API

**File:** `redirect.go` lines 327-335, 375-390

`Redirect.To()` and `Redirect.Back()` accept arbitrary URLs without validation.
This is intentional — these are framework APIs that developers call with
controlled inputs. Open redirect risk exists only if developers pass
unsanitized user input directly to these methods. This is consistent with other
web frameworks (Express.js `res.redirect()`, Django `HttpResponseRedirect()`).

### Proxy Middleware SSRF Surface

**File:** `middleware/proxy/proxy.go`

The proxy middleware forwards requests to configured backend servers. The
target addresses are set by the developer at configuration time, not derived
from user input. SSRF risk exists only if the developer passes user-controlled
input as proxy targets. This is the expected behavior of a reverse proxy.

### KeyAuth Timing Attack Surface

**File:** `middleware/keyauth/keyauth.go` lines 47-54

The KeyAuth middleware delegates API key validation to a user-provided
`Validator` function. If the developer implements this function using
non-constant-time comparison (e.g., `==`), timing attacks are possible. The
framework should document the requirement for constant-time comparison and
provide examples using `crypto/subtle`.

---

## Methodology

The audit covered:

1. **Input handling**: Request parsing, binding (JSON, XML, form, multipart),
   path parameters
2. **Output handling**: Response headers, redirects, file serving,
   Content-Disposition
3. **Security middleware**: CORS, CSRF, helmet, rate limiter, authentication
4. **Session management**: Cookie security, ID generation, fixation protection
5. **Network handling**: Proxy forwarding, IP extraction, TLS configuration

Tools used:

- Manual code review
- Go runtime verification of XML/JSON parsing limits
- fasthttp source code analysis for header safety
- Cross-reference with OWASP security guidelines

---

## Conclusion

The Fiber framework has a solid security posture. The core framework properly
mitigates common web vulnerabilities through a combination of fasthttp's
built-in protections and Go standard library safety guarantees. The findings
identified are primarily configuration-level improvements rather than
exploitable vulnerabilities.

**Overall Risk Assessment: LOW**

No critical or high-severity exploitable vulnerabilities were found in the
default framework configuration. The identified medium-severity findings
require specific misconfiguration to be exploitable.
