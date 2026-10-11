# headersec

Grades a live URL's HTTP response security headers. securityheaders.com
answers exactly this question and answers it well — but it is a website,
with no CLI and no API, so the one place you actually want the check (a
CI job, a pre-release script, a cron loop over your own domains) is the
one place you can't put it. This is a single binary that fetches the real
URL, grades the response, and exits non-zero when the grade slips.

## Installation

```sh
cargo install --path .
```

## Usage

```bash
headersec github.com                          # bare hostname is assumed https://
headersec https://example.com/ https://api.example.com/v1/
headersec example.com --json                  # machine-readable, for CI
headersec example.com --min-grade A           # exit 1 below this grade (default B)
headersec https://stripe.com/ --no-redirect   # grade the 3xx itself, not its destination
headersec github.com --full                   # don't truncate long CSP values
```

Exit code `1` if any URL grades below `--min-grade`, or if a URL couldn't
be fetched at all — cron/CI-friendly by design, same as this workspace's
`certwatch`.

It issues a real `GET`, not a `HEAD`: plenty of servers, CDNs and
frameworks attach security headers only on the HTML response path and
answer `HEAD` from a barer one, so grading a `HEAD` reports headers no
browser ever sees. Redirects are followed by default and the final URL is
the one graded — `--no-redirect` when you specifically want to know what
the `http://` entry point itself sends.

## What it checks, and why each one matters

Six graded headers:

- **`Content-Security-Policy`** — the only header that actually stops an
  injected `<script>` from running. Missing is a fail; `'unsafe-inline'`
  or `'unsafe-eval'` in the effective script source is a warn (unless a
  nonce or hash is also present, which makes browsers ignore
  `'unsafe-inline'` entirely — the documented backwards-compatibility
  recipe, not a hole); so is a policy with neither `default-src` nor
  `script-src`, which constrains nothing about scripts. `Report-Only`
  alone is a warn: it reports violations and blocks nothing.
- **`Strict-Transport-Security`** — stops an `http://` link or typed
  address being downgraded and intercepted before the redirect happens.
  Graded on substance, not presence: `max-age=0` is a fail (it switches
  HSTS *off*), under six months is a warn (a browser that hasn't visited
  lately falls back to plaintext), and a long `max-age` without
  `includeSubDomains` is still a warn — any subdomain, including one that
  doesn't exist yet, can be served over plaintext and set cookies for the
  parent. `preload` is reported. Over plain HTTP the check is `N/A` and
  is removed from the denominator, because browsers ignore the header
  there and scoring it as a failure would be meaningless.
- **`X-Content-Type-Options: nosniff`** — without it, a user-uploaded
  file served as `text/plain` can be sniffed into `text/html` and
  executed as script inside your own origin. `nosniff` is the only value
  browsers act on, so any other value is a warn.
- **`X-Frame-Options`, or CSP `frame-ancestors`** — clickjacking. CSP
  `frame-ancestors` is the standardised successor and browsers that
  support it ignore `X-Frame-Options` outright, so either one passes.
  `ALLOW-FROM` is a warn: Chrome never implemented it and Firefox removed
  it, so it is not protection. `frame-ancestors *` is a warn for the
  obvious reason.
- **`Referrer-Policy`** — keeps the full URL (path and query, which is
  where session IDs and reset tokens end up) out of third parties' logs.
  A comma-separated value is a fallback chain and browsers use the last
  token they understand, so that's the one graded. `unsafe-url` fails;
  `no-referrer-when-downgrade` — the old browser default, which still
  sends the whole URL to any other HTTPS origin — warns; missing warns,
  because modern browsers do have a safe default but older clients don't.
- **`Permissions-Policy`** — scopes camera, microphone, geolocation and
  payment for the page and anything it embeds. Missing is a warn. The
  deprecated `Feature-Policy` predecessor doesn't count as a substitute.

Plus **risk flags** — things that are dangerous by being present, and the
one thing that is dangerous by being absent:

- **`Access-Control-Allow-Origin: *` with
  `Access-Control-Allow-Credentials: true`** — a fail. Browsers reject
  that exact pair, but a server sending it is configured to share
  authenticated responses cross-origin and is only being saved by the
  browser refusing; a reflected-origin variant of the same config would
  not be. Wildcard without credentials, or `null` (the origin of
  sandboxed iframes and `file://` documents, so any attacker page can
  obtain it), are warns.
- **HSTS entirely absent on an HTTPS origin** — a fail, raised here as
  well as in the graded section, because "HTTPS but strippable" is a
  different and worse statement than "one header missing."
- **Version disclosure** — `X-Powered-By`, `X-AspNet-Version`,
  `X-AspNetMvc-Version`, `X-Generator`, and a `Server` header carrying a
  version number. Warns, never fails: this isn't a vulnerability, it just
  narrows a CVE search to your exact build. `Server: nginx` is fine;
  `Server: nginx/1.18.0 (Ubuntu)` is flagged.

**Grading.** Each applicable graded header scores 2 for a pass, 1 for a
warn, 0 for a fail; the percentage maps to A+ (100) / A (90) / B (75) /
C (60) / D (45) / E (30) / F. A fail-level risk flag caps the overall
grade at C however perfect the six headers are, and any risk flag at all
takes A+ down to A — A+ means "nothing to report."

## Status: built, verified against real live endpoints, with the good and bad cases both real

- **35 unit tests** (`cargo test --lib`), all on hand-built header sets
  with no socket involved — which is the point of keeping `grade.rs`
  pure. A fully-hardened set scoring 100% / A+ with every check passing;
  a completely empty set over HTTPS failing CSP/HSTS/`X-Content-Type-
  Options`/framing while warning (not failing) on Referrer-Policy and
  Permissions-Policy, grading F; and the tricky ones: **HSTS present but
  `max-age=300`** graded a warn and costing exactly one point rather than
  failing an otherwise perfect site, `max-age=0` graded a *fail* because
  it actively turns HSTS off, a year-long `max-age` still warned for
  missing `includeSubDomains`, **CSP with `'unsafe-inline' 'unsafe-eval'`**
  warned — but the same CSP **with a nonce alongside `'unsafe-inline'`
  passing**, since browsers ignore `'unsafe-inline'` when a nonce is
  present and warning there would be a false positive. Also: `script-src-
  elem` confirmed *not* to satisfy a lookup for `script-src` (exact
  directive matching, not substring); `Referrer-Policy: origin-when-
  cross-origin, strict-origin-when-cross-origin` graded on the last token
  because that's the one browsers apply; HSTS excluded from the
  denominator rather than zeroed over plain HTTP; and the wildcard-CORS-
  with-credentials pair capping a 100%-scoring site at C.
- **4 end-to-end tests against a real HTTP server** (`tests/
  local_server.rs`) — a `TcpListener` the test binds on loopback and
  answers itself, so the full client + header-collection path is
  exercised with no internet needed and these run in ordinary
  `cargo test`. Same server, same code path, three header sets: one
  deliberately sending **none** of these headers → **F**; one hardened →
  **A+**, with the raw CSP string confirmed to survive the round trip
  byte-for-byte; one adding the `ACAO: *` + credentials pair and
  `X-Powered-By` → still 100% on the six graded headers but **capped at
  C** by the risk flag. Plus a known-closed port producing a clean error
  naming the target, not a hang or a panic.
- **5 live-internet tests** (`tests/live.rs`), every one `#[ignore]`d so
  a restricted CI runner still passes a plain `cargo test`; run them with
  `cargo test --test live -- --ignored`. All 5 pass against the real
  internet as of writing.

Real output, real headers, quoted as observed — this is what the six
sites below actually sent:

- **`github.com` → A (92%)**, the strong real-world case. Real values:
  `strict-transport-security: max-age=31536000; includeSubdomains; preload`
  (pass), `x-content-type-options: nosniff` (pass), a `content-security-
  policy` beginning `default-src 'none'; base-uri 'self'; child-src
  github.githubassets.com …` (pass), framing satisfied by that policy's
  `frame-ancestors 'none'` rather than by `x-frame-options: deny`, and
  `referrer-policy: origin-when-cross-origin, strict-origin-when-cross-
  origin` (pass on the last token). The single point it loses is a
  genuinely absent **`Permissions-Policy`** — github really doesn't send
  one. Its `server: github.com` carries no version, so it is correctly
  *not* flagged.
- **`example.com` → F (17%)**, a real, live, non-toy HTTPS origin that
  genuinely sends none of these. Its entire response header set is
  `date`, `content-type`, `server: cloudflare`, `last-modified`, `allow`,
  `accept-ranges`, `age`, `cf-cache-status`, `cf-ray` — not one security
  header among them. Four fails, two warns, plus the `FAIL` risk flag for
  an HTTPS origin with no HSTS at all.
- **`httpbin.org` → F (17%)** and the one that proves the dangerous-
  header detection on a real server, not a fixture: it really does send
  `access-control-allow-origin: *` together with `access-control-allow-
  credentials: true`, both flagged as a `FAIL`, alongside `server:
  gunicorn/19.9.0` flagged as version disclosure.
- **`www.mozilla.org` → B (75%)**, the useful middle case. Real
  `strict-transport-security: max-age=31536000` — a full year, but with
  **no `includeSubDomains`**, correctly a warn rather than a pass. Its
  real CSP contains `script-src 'self' 'unsafe-eval' 'unsafe-inline'
  *.google-analytics.com …` → warn, and `frame-ancestors 'none'` → pass
  for framing. No `Permissions-Policy`.
- **`www.cloudflare.com` → A (92%)**: `strict-transport-security:
  max-age=31536000; includeSubDomains` (pass, no `preload`), and the only
  one of these that sends a real **`permissions-policy: geolocation=(),
  camera=(), microphone=()`**. Its CSP — `default-src 'self'; script-src
  'self' 'unsafe-inline' 'unsafe-eval' https://static.cloudflareinsights.com
  …` — is the one thing warned.
- **`stripe.com` → B (84%)**, which exercises redirect handling for real:
  `https://stripe.com/` answers **`307`** to `https://stripe.com/in`, and
  the tool reports that it followed it and grades the destination. Real
  `strict-transport-security: max-age=63072000; includeSubDomains;
  preload` (pass) and `frame-ancestors https://app.contentful.com 'self'`
  (pass); warned on its real `referrer-policy: no-referrer-when-
  downgrade`. With `--no-redirect` the same command reports the `307`
  itself instead, confirming the flag does what it says.
- **HTTPS-vs-HTTP behaviour verified on real plain-HTTP sites**:
  `http://info.cern.ch/` and `http://neverssl.com/` are both still served
  over plain HTTP, and on both the HSTS check is correctly reported `N/A`
  and dropped from the denominator (F at 20%, from 5 applicable checks)
  rather than counted as a failure — the difference against `example.com`'s
  17% over 6 checks is exactly that exclusion. `neverssl.com`'s real
  `Server: Apache/2.4.68 ()` is flagged for version disclosure, while
  `example.com`'s bare `server: cloudflare` is not.

**Not done / deliberately deferred**: cookie flags (`Set-Cookie` with
`Secure`/`HttpOnly`/`SameSite`) — securityheaders.com reports them and
they belong in a v2, but they're per-cookie rather than per-response and
need their own report shape; checking whether an `http://` origin
actually *redirects* to HTTPS (this grades whatever response it lands on
and says so, it doesn't separately probe the plaintext entry point);
`Cross-Origin-Opener-Policy` / `Cross-Origin-Embedder-Policy` /
`Cross-Origin-Resource-Policy`, which are real and increasingly expected
but are about isolation rather than the classic six and would want their
own section rather than being folded into this score; CSP analysis deeper
than script sources (`object-src`, `base-uri`, dangling-markup and
JSONP-endpoint allowlist checks are where a real CSP evaluator earns its
keep, and this is not one); and any concurrency — URLs are checked one at
a time, fine for a handful from cron, worth parallelising for hundreds.
