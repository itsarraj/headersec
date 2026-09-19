//! The grading rules. Entirely pure: in goes a `Headers` set plus whether
//! the response came over HTTPS, out comes an `Assessment`. Nothing here
//! opens a socket, which is what makes every rule below directly
//! unit-testable against a hand-built header set.

use crate::headers::Headers;

/// Six months. Below this an HSTS policy is barely doing its job — a
/// browser that hasn't visited recently falls back to plaintext, which is
/// exactly the window HSTS exists to close.
pub const HSTS_MIN_MAX_AGE: u64 = 15_768_000;

/// One year — the value the browser preload lists require.
pub const HSTS_PRELOAD_MAX_AGE: u64 = 31_536_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Pass,
    Warn,
    Fail,
    /// The check doesn't apply to this response (HSTS over plain HTTP).
    /// Scored by being excluded from the total, not by being given zero.
    NotApplicable,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::Pass => "PASS",
            Level::Warn => "WARN",
            Level::Fail => "FAIL",
            Level::NotApplicable => "N/A ",
        }
    }

    fn points(self) -> Option<u32> {
        match self {
            Level::Pass => Some(2),
            Level::Warn => Some(1),
            Level::Fail => Some(0),
            Level::NotApplicable => None,
        }
    }
}

/// Ordered worst-to-best so `a.min(b)` is "the worse of the two grades",
/// which is how the risk-flag cap is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grade {
    F,
    E,
    D,
    C,
    B,
    A,
    APlus,
}

impl Grade {
    pub fn as_str(self) -> &'static str {
        match self {
            Grade::F => "F",
            Grade::E => "E",
            Grade::D => "D",
            Grade::C => "C",
            Grade::B => "B",
            Grade::A => "A",
            Grade::APlus => "A+",
        }
    }

    pub fn parse(s: &str) -> Option<Grade> {
        match s.trim().to_ascii_uppercase().as_str() {
            "A+" | "APLUS" => Some(Grade::APlus),
            "A" => Some(Grade::A),
            "B" => Some(Grade::B),
            "C" => Some(Grade::C),
            "D" => Some(Grade::D),
            "E" => Some(Grade::E),
            "F" => Some(Grade::F),
            _ => None,
        }
    }

    fn from_percent(pct: u32) -> Grade {
        match pct {
            100 => Grade::APlus,
            90..=99 => Grade::A,
            75..=89 => Grade::B,
            60..=74 => Grade::C,
            45..=59 => Grade::D,
            30..=44 => Grade::E,
            _ => Grade::F,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Display name of the header (canonical casing), or a short label for
    /// a risk flag that isn't tied to one header.
    pub header: &'static str,
    pub level: Level,
    /// The raw value actually observed, if the header was present.
    pub value: Option<String>,
    /// One line on what this means. Always populated.
    pub note: String,
}

impl Finding {
    fn new(header: &'static str, level: Level, value: Option<&str>, note: &str) -> Finding {
        Finding {
            header,
            level,
            value: value.map(str::to_string),
            note: note.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// The six graded headers, always in a fixed order.
    pub core: Vec<Finding>,
    /// Dangerous things actually present (plus missing HSTS on an HTTPS
    /// origin, which is dangerous by absence). Not scored directly — a
    /// `Fail` here caps the overall grade, a `Warn` here blocks A+.
    pub risks: Vec<Finding>,
    pub score_percent: u32,
    pub grade: Grade,
}

impl Assessment {
    pub fn level_of(&self, header: &str) -> Option<Level> {
        self.core
            .iter()
            .find(|f| f.header.eq_ignore_ascii_case(header))
            .map(|f| f.level)
    }
}

// ---------------------------------------------------------------------------
// Small parsers for the two headers that have real internal structure.
// ---------------------------------------------------------------------------

/// Pulls one directive's value out of a CSP string. `csp_directive("default-src
/// 'self'; script-src 'unsafe-inline'", "script-src")` -> `Some("'unsafe-inline'")`.
/// Returns `Some("")` for a valueless directive like `upgrade-insecure-requests`.
pub fn csp_directive<'a>(csp: &'a str, name: &str) -> Option<&'a str> {
    for part in csp.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (directive, rest) = match part.split_once(char::is_whitespace) {
            Some((d, r)) => (d, r.trim()),
            None => (part, ""),
        };
        if directive.eq_ignore_ascii_case(name) {
            return Some(rest);
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hsts {
    pub max_age: Option<u64>,
    pub include_subdomains: bool,
    pub preload: bool,
}

/// Parses a `Strict-Transport-Security` value. Directives are
/// semicolon-separated and case-insensitive; `max-age` may be quoted.
pub fn parse_hsts(value: &str) -> Hsts {
    let mut out = Hsts::default();
    for part in value.split(';') {
        let part = part.trim();
        if part.eq_ignore_ascii_case("includeSubDomains") {
            out.include_subdomains = true;
        } else if part.eq_ignore_ascii_case("preload") {
            out.preload = true;
        } else if let Some((k, v)) = part.split_once('=') {
            if k.trim().eq_ignore_ascii_case("max-age") {
                out.max_age = v.trim().trim_matches('"').parse::<u64>().ok();
            }
        }
    }
    out
}

fn humanize_seconds(secs: u64) -> String {
    const DAY: u64 = 86_400;
    if secs >= 365 * DAY {
        let years = secs as f64 / (365.0 * DAY as f64);
        format!("{years:.1} years")
    } else if secs >= DAY {
        format!("{} days", secs / DAY)
    } else {
        format!("{secs} seconds")
    }
}

// ---------------------------------------------------------------------------
// The six graded checks.
// ---------------------------------------------------------------------------

fn check_csp(h: &Headers) -> Finding {
    const NAME: &str = "Content-Security-Policy";

    let all = h.get_all("content-security-policy");
    let Some(&csp) = all.first() else {
        // Report-Only sends violation reports but enforces nothing, so it
        // is genuinely better than silence and genuinely not protection.
        if let Some(ro) = h.get("content-security-policy-report-only") {
            return Finding::new(
                NAME,
                Level::Warn,
                Some(ro),
                "only Content-Security-Policy-Report-Only is set — violations are reported \
                 but nothing is actually blocked",
            );
        }
        return Finding::new(
            NAME,
            Level::Fail,
            None,
            "missing — nothing constrains where scripts, styles or frames may be loaded from, \
             so any injected markup runs with the page's full privileges",
        );
    };

    let multiple = if all.len() > 1 {
        format!(
            " ({} policies sent; browsers enforce the intersection, only the first is graded)",
            all.len()
        )
    } else {
        String::new()
    };

    // `script-src` wins over `default-src` for scripts; if neither exists
    // the policy says nothing at all about script loading.
    let script_src = csp_directive(csp, "script-src").or_else(|| csp_directive(csp, "default-src"));

    let Some(script_src) = script_src else {
        return Finding::new(
            NAME,
            Level::Warn,
            Some(csp),
            &format!(
                "present but has neither default-src nor script-src, so it places no limit \
                 on script sources — the directive that actually stops XSS{multiple}"
            ),
        );
    };

    let lowered = script_src.to_ascii_lowercase();
    let unsafe_inline = lowered.contains("'unsafe-inline'");
    let unsafe_eval = lowered.contains("'unsafe-eval'");
    // A nonce or hash makes browsers ignore 'unsafe-inline' entirely, so a
    // policy carrying both is fine on modern browsers and only there as a
    // fallback for old ones.
    let has_nonce_or_hash =
        lowered.contains("'nonce-") || lowered.contains("'sha256-") || lowered.contains("'sha384-");
    let wildcard = script_src.split_whitespace().any(|s| s == "*");

    if wildcard {
        return Finding::new(
            NAME,
            Level::Warn,
            Some(csp),
            &format!(
                "script sources are `*` — any origin may serve script, which is close to \
                      having no policy at all{multiple}"
            ),
        );
    }
    if unsafe_inline && !has_nonce_or_hash {
        let also = if unsafe_eval {
            " and 'unsafe-eval'"
        } else {
            ""
        };
        return Finding::new(
            NAME,
            Level::Warn,
            Some(csp),
            &format!("allows 'unsafe-inline'{also} for scripts with no nonce or hash to \
                      override it, which is the main injection path CSP is meant to close{multiple}"),
        );
    }
    if unsafe_eval {
        return Finding::new(
            NAME,
            Level::Warn,
            Some(csp),
            &format!(
                "allows 'unsafe-eval', so string-to-code paths (eval, `new Function`) \
                      stay available to injected content{multiple}"
            ),
        );
    }

    Finding::new(
        NAME,
        Level::Pass,
        Some(csp),
        &format!(
            "enforced, and constrains script sources without 'unsafe-inline' or \
                  'unsafe-eval'{multiple}"
        ),
    )
}

fn check_hsts(h: &Headers, https: bool) -> Finding {
    const NAME: &str = "Strict-Transport-Security";

    if !https {
        return Finding::new(
            NAME,
            Level::NotApplicable,
            h.get("strict-transport-security"),
            "not applicable — this response came over plain HTTP, where browsers ignore HSTS \
             entirely. Serve the site over HTTPS first",
        );
    }

    let Some(value) = h.get("strict-transport-security") else {
        return Finding::new(
            NAME,
            Level::Fail,
            None,
            "missing on an HTTPS origin — a first request typed as `http://`, or any \
             plaintext link, is still downgradeable and interceptable",
        );
    };

    let hsts = parse_hsts(value);
    let Some(max_age) = hsts.max_age else {
        return Finding::new(
            NAME,
            Level::Fail,
            Some(value),
            "no parseable max-age directive, so the whole header is ignored by browsers",
        );
    };

    if max_age == 0 {
        return Finding::new(
            NAME,
            Level::Fail,
            Some(value),
            "max-age=0 explicitly tells browsers to forget the HSTS policy — this actively \
             switches the protection off",
        );
    }
    if max_age < HSTS_MIN_MAX_AGE {
        return Finding::new(
            NAME,
            Level::Warn,
            Some(value),
            &format!(
                "max-age is only {} — under the 6 month baseline, so a browser that hasn't \
                 visited lately silently drops back to plaintext",
                humanize_seconds(max_age)
            ),
        );
    }
    if !hsts.include_subdomains {
        return Finding::new(
            NAME,
            Level::Warn,
            Some(value),
            &format!(
                "max-age is {} but includeSubDomains is absent, so any subdomain \
                 (including one that doesn't exist yet) can still be served over plaintext \
                 and used to set cookies for the parent",
                humanize_seconds(max_age)
            ),
        );
    }

    let preload_note = if hsts.preload {
        ", preload"
    } else if max_age >= HSTS_PRELOAD_MAX_AGE {
        " — long enough to submit to the browser preload list, which `preload` would then request"
    } else {
        ""
    };
    Finding::new(
        NAME,
        Level::Pass,
        Some(value),
        &format!(
            "max-age {}, includeSubDomains{}",
            humanize_seconds(max_age),
            preload_note
        ),
    )
}

fn check_content_type_options(h: &Headers) -> Finding {
    const NAME: &str = "X-Content-Type-Options";

    match h.get("x-content-type-options") {
        Some(v) if v.eq_ignore_ascii_case("nosniff") => Finding::new(
            NAME,
            Level::Pass,
            Some(v),
            "nosniff — browsers honour the declared Content-Type instead of guessing it",
        ),
        Some(v) => Finding::new(
            NAME,
            Level::Warn,
            Some(v),
            "present but not `nosniff`; `nosniff` is the only value browsers act on, so this \
             header does nothing as written",
        ),
        None => Finding::new(
            NAME,
            Level::Fail,
            None,
            "missing — a user-uploaded file served as text/plain can be sniffed into \
             text/html and executed as a script in the site's own origin",
        ),
    }
}

fn check_framing(h: &Headers) -> Finding {
    const NAME: &str = "X-Frame-Options";

    // The modern replacement. If CSP already says frame-ancestors, browsers
    // that support it ignore X-Frame-Options outright, so this is a pass
    // regardless of whether the legacy header is there.
    let frame_ancestors = h
        .get_all("content-security-policy")
        .iter()
        .find_map(|csp| csp_directive(csp, "frame-ancestors").map(str::to_string));

    if let Some(fa) = frame_ancestors {
        if fa.split_whitespace().any(|s| s == "*") {
            return Finding::new(
                NAME,
                Level::Warn,
                Some(&format!("CSP frame-ancestors {fa}")),
                "CSP sets frame-ancestors to `*`, which permits framing by any site — \
                 the header is present but grants exactly what clickjacking needs",
            );
        }
        let legacy = match h.get("x-frame-options") {
            Some(xfo) => format!(" (legacy X-Frame-Options: {xfo} also sent)"),
            None => String::new(),
        };
        return Finding::new(
            NAME,
            Level::Pass,
            Some(&format!("CSP frame-ancestors {fa}")),
            &format!(
                "CSP frame-ancestors is set, the modern replacement for X-Frame-Options{legacy}"
            ),
        );
    }

    match h.get("x-frame-options") {
        Some(v) if v.eq_ignore_ascii_case("deny") || v.eq_ignore_ascii_case("sameorigin") => {
            Finding::new(
                NAME,
                Level::Pass,
                Some(v),
                "framing is restricted, so the page can't be invisibly overlaid on an \
                 attacker's site to steal clicks. Consider CSP frame-ancestors as well, \
                 which is the standardised successor",
            )
        }
        Some(v) if v.to_ascii_lowercase().starts_with("allow-from") => Finding::new(
            NAME,
            Level::Warn,
            Some(v),
            "ALLOW-FROM was never implemented by Chrome and was removed from Firefox — no \
             current browser honours it, so this is effectively no protection. Use CSP \
             frame-ancestors",
        ),
        Some(v) => Finding::new(
            NAME,
            Level::Warn,
            Some(v),
            "present but not a value browsers recognise (DENY or SAMEORIGIN), so it is \
             ignored",
        ),
        None => Finding::new(
            NAME,
            Level::Fail,
            None,
            "missing, and CSP sets no frame-ancestors either — the page can be framed by \
             any site, which is what clickjacking needs",
        ),
    }
}

fn check_referrer_policy(h: &Headers) -> Finding {
    const NAME: &str = "Referrer-Policy";

    let Some(value) = h.get("referrer-policy") else {
        return Finding::new(
            NAME,
            Level::Warn,
            None,
            "missing — modern browsers default to strict-origin-when-cross-origin so this \
             is no longer a disaster, but the default is not guaranteed and older clients \
             will leak the full URL, including anything sensitive in the path or query",
        );
    };

    // A comma-separated list is a fallback chain: browsers use the last
    // token they understand, so that is the one that actually applies.
    let effective = value
        .split(',')
        .map(str::trim)
        .rfind(|s| !s.is_empty())
        .unwrap_or("");

    if effective.eq_ignore_ascii_case("unsafe-url") {
        return Finding::new(
            NAME,
            Level::Fail,
            Some(value),
            "`unsafe-url` sends the full URL — path and query included — to every third \
             party the page touches, including over plaintext",
        );
    }
    if effective.eq_ignore_ascii_case("no-referrer-when-downgrade") {
        return Finding::new(
            NAME,
            Level::Warn,
            Some(value),
            "`no-referrer-when-downgrade` was the old browser default: it still sends the \
             full URL (path and query) to any other HTTPS origin",
        );
    }

    const RECOGNISED: &[&str] = &[
        "no-referrer",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    ];
    if RECOGNISED.iter().any(|p| effective.eq_ignore_ascii_case(p)) {
        Finding::new(
            NAME,
            Level::Pass,
            Some(value),
            "cross-origin requests don't carry the full URL, so path and query stay out of \
             third parties' logs",
        )
    } else {
        Finding::new(
            NAME,
            Level::Warn,
            Some(value),
            "not a policy token browsers recognise; an unrecognised value is ignored and \
             the browser default applies instead",
        )
    }
}

fn check_permissions_policy(h: &Headers) -> Finding {
    const NAME: &str = "Permissions-Policy";

    if let Some(v) = h.get("permissions-policy") {
        if v.is_empty() {
            return Finding::new(
                NAME,
                Level::Warn,
                Some(v),
                "present but empty, so it grants and denies nothing",
            );
        }
        return Finding::new(
            NAME,
            Level::Pass,
            Some(v),
            "powerful features are explicitly scoped, so injected or third-party frames \
             can't reach for camera, microphone or geolocation on this origin",
        );
    }
    if let Some(v) = h.get("feature-policy") {
        return Finding::new(
            NAME,
            Level::Warn,
            Some(&format!("Feature-Policy: {v}")),
            "only the deprecated Feature-Policy predecessor is set; current browsers \
             expect Permissions-Policy and ignore this",
        );
    }
    Finding::new(
        NAME,
        Level::Warn,
        None,
        "missing — nothing restricts which features (camera, microphone, geolocation, \
         payment) this page or anything it embeds may request",
    )
}

// ---------------------------------------------------------------------------
// Risk flags: things that are dangerous by being present, plus the one
// thing that is dangerous by being absent.
// ---------------------------------------------------------------------------

/// Headers whose presence hands an attacker a version number to match
/// against a CVE list. Warn, never fail — disclosure is a real finding but
/// not a vulnerability on its own.
const VERSION_DISCLOSING_HEADERS: &[(&str, &str)] = &[
    (
        "x-powered-by",
        "discloses the application stack and often its exact version",
    ),
    (
        "x-aspnet-version",
        "discloses the exact ASP.NET runtime version",
    ),
    (
        "x-aspnetmvc-version",
        "discloses the exact ASP.NET MVC version",
    ),
    (
        "x-generator",
        "discloses the CMS or generator and often its version",
    ),
    ("x-drupal-dynamic-cache", "identifies the site as Drupal"),
];

fn check_risks(h: &Headers, https: bool) -> Vec<Finding> {
    let mut risks = Vec::new();

    // The classic CORS misconfiguration. `*` with credentials is rejected
    // by browsers outright, so a server sending it is either broken or has
    // a matching reflected-origin path that is *not* rejected.
    let acao = h.get("access-control-allow-origin");
    let credentialed = h
        .get("access-control-allow-credentials")
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));

    match acao {
        Some(v) if v.trim() == "*" && credentialed => risks.push(Finding::new(
            "Access-Control-Allow-Origin",
            Level::Fail,
            Some("* (with Access-Control-Allow-Credentials: true)"),
            "wildcard origin combined with credentialed responses. Browsers reject this \
             exact pair, which means the server is configured to share authenticated \
             responses cross-origin and is only being saved by the browser refusing it — \
             a reflected-origin variant of the same config would not be",
        )),
        Some(v) if v.trim() == "*" => risks.push(Finding::new(
            "Access-Control-Allow-Origin",
            Level::Warn,
            Some(v),
            "any origin may read this response. Fine for genuinely public assets, a data \
             leak for anything user-specific",
        )),
        Some(v) if v.trim().eq_ignore_ascii_case("null") => risks.push(Finding::new(
            "Access-Control-Allow-Origin",
            Level::Warn,
            Some(v),
            "`null` is the origin of sandboxed iframes and `file://` documents, so any \
             attacker page can obtain it — it is not the safe placeholder it looks like",
        )),
        _ => {}
    }

    if credentialed && acao.is_none() {
        risks.push(Finding::new(
            "Access-Control-Allow-Credentials",
            Level::Warn,
            h.get("access-control-allow-credentials"),
            "credentialed CORS is switched on with no Access-Control-Allow-Origin on this \
             response — check whether the origin is being reflected on other routes",
        ));
    }

    if https && !h.has("strict-transport-security") {
        risks.push(Finding::new(
            "Strict-Transport-Security",
            Level::Fail,
            None,
            "an HTTPS origin with no HSTS at all: every `http://` entry point stays \
             downgradeable, so a network attacker can strip TLS before the redirect ever \
             happens",
        ));
    }

    for (name, why) in VERSION_DISCLOSING_HEADERS {
        if let Some(v) = h.get(name) {
            risks.push(Finding::new(
                canonical_name(name),
                Level::Warn,
                Some(v),
                why,
            ));
        }
    }

    // `Server: nginx` is fine; `Server: nginx/1.18.0 (Ubuntu)` is a CVE
    // shopping list. Only flag when a version number is actually attached.
    if let Some(v) = h.get("server") {
        if v.contains('/') && v.chars().any(|c| c.is_ascii_digit()) {
            risks.push(Finding::new(
                "Server",
                Level::Warn,
                Some(v),
                "includes a version number, which narrows a CVE search to the exact build",
            ));
        }
    }

    risks
}

fn canonical_name(lower: &str) -> &'static str {
    match lower {
        "x-powered-by" => "X-Powered-By",
        "x-aspnet-version" => "X-AspNet-Version",
        "x-aspnetmvc-version" => "X-AspNetMvc-Version",
        "x-generator" => "X-Generator",
        "x-drupal-dynamic-cache" => "X-Drupal-Dynamic-Cache",
        _ => "Header",
    }
}

// ---------------------------------------------------------------------------

/// Grades a response. `https` is whether the *final* response (after any
/// redirects) was served over TLS — it decides whether HSTS is graded at
/// all, since browsers ignore the header over plain HTTP.
pub fn analyze(headers: &Headers, https: bool) -> Assessment {
    let core = vec![
        check_csp(headers),
        check_hsts(headers, https),
        check_content_type_options(headers),
        check_framing(headers),
        check_referrer_policy(headers),
        check_permissions_policy(headers),
    ];
    let risks = check_risks(headers, https);

    let mut earned = 0;
    let mut possible = 0;
    for f in &core {
        if let Some(p) = f.level.points() {
            earned += p;
            possible += 2;
        }
    }
    // `possible` can only be 0 if every check were N/A, which can't happen
    // (five of the six always apply), but don't divide by it blindly.
    let score_percent = if possible == 0 {
        0
    } else {
        (earned * 100).div_ceil(possible).min(100)
    };

    let mut grade = Grade::from_percent(score_percent);
    if risks.iter().any(|r| r.level == Level::Fail) {
        // A genuine misconfiguration caps the grade however good the rest
        // of the header set is.
        grade = grade.min(Grade::C);
    } else if !risks.is_empty() && grade == Grade::APlus {
        // A+ means "nothing to report", so any flag at all takes it off.
        grade = Grade::A;
    }

    Assessment {
        core,
        risks,
        score_percent,
        grade,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hardened() -> Headers {
        [
            (
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'",
            ),
            (
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains; preload",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            (
                "Permissions-Policy",
                "geolocation=(), camera=(), microphone=()",
            ),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn fully_hardened_set_is_all_pass_and_a_plus() {
        let a = analyze(&hardened(), true);
        assert!(
            a.core.iter().all(|f| f.level == Level::Pass),
            "expected every core check to pass, got {:?}",
            a.core
                .iter()
                .map(|f| (f.header, f.level))
                .collect::<Vec<_>>()
        );
        assert_eq!(a.score_percent, 100);
        assert_eq!(a.grade, Grade::APlus);
        assert!(a.risks.is_empty(), "no risk flags expected: {:?}", a.risks);
    }

    #[test]
    fn every_core_finding_carries_the_observed_value_and_a_note() {
        let a = analyze(&hardened(), true);
        for f in &a.core {
            assert!(!f.note.is_empty(), "{} has no note", f.header);
            assert!(f.value.is_some(), "{} lost its observed value", f.header);
        }
    }

    #[test]
    fn empty_header_set_over_https_fails_everything_scoreable_and_grades_f() {
        let a = analyze(&Headers::new(), true);
        assert_eq!(a.level_of("Content-Security-Policy"), Some(Level::Fail));
        assert_eq!(a.level_of("Strict-Transport-Security"), Some(Level::Fail));
        assert_eq!(a.level_of("X-Content-Type-Options"), Some(Level::Fail));
        assert_eq!(a.level_of("X-Frame-Options"), Some(Level::Fail));
        // Missing Referrer-Policy / Permissions-Policy are warnings, not
        // failures: browsers now have a safe referrer default, and an
        // absent Permissions-Policy isn't itself an exploit path.
        assert_eq!(a.level_of("Referrer-Policy"), Some(Level::Warn));
        assert_eq!(a.level_of("Permissions-Policy"), Some(Level::Warn));
        assert_eq!(a.grade, Grade::F);
        // 2 of 12 points.
        assert!(a.score_percent < 30, "got {}", a.score_percent);
        // ...and the HTTPS-without-HSTS condition is surfaced as a risk.
        assert!(a
            .risks
            .iter()
            .any(|r| r.header == "Strict-Transport-Security" && r.level == Level::Fail));
    }

    #[test]
    fn over_plain_http_hsts_is_not_applicable_and_is_excluded_from_the_score() {
        let mut h = hardened();
        // An HTTP response that somehow still carries HSTS: browsers ignore
        // it, so grading it as a pass would be flattering a site that isn't
        // protected at all.
        let a = analyze(&h, false);
        assert_eq!(
            a.level_of("Strict-Transport-Security"),
            Some(Level::NotApplicable)
        );
        // Five applicable checks, all passing, so still 100% — the N/A
        // check is removed from the denominator, not scored as zero.
        assert_eq!(a.score_percent, 100);

        h = [("X-Content-Type-Options", "nosniff")]
            .into_iter()
            .collect();
        let a = analyze(&h, false);
        // 1 pass + 2 warns out of 5 applicable checks = 4/10.
        assert_eq!(a.score_percent, 40);
        assert_eq!(a.grade, Grade::E);
        // No HSTS risk flag over plain HTTP — it would be noise.
        assert!(!a
            .risks
            .iter()
            .any(|r| r.header == "Strict-Transport-Security"));
    }

    // --- the tricky ones ---------------------------------------------------

    #[test]
    fn hsts_present_but_max_age_too_short_is_a_warn_not_a_pass() {
        // Everything else about this site is perfect; only the HSTS
        // lifetime is too short to be worth much.
        let h: Headers = hardened()
            .iter()
            .map(|(k, v)| {
                if k == "strict-transport-security" {
                    (k, "max-age=300; includeSubDomains")
                } else {
                    (k, v)
                }
            })
            .collect();
        let a = analyze(&h, true);
        assert_eq!(a.level_of("Strict-Transport-Security"), Some(Level::Warn));
        let f = a
            .core
            .iter()
            .find(|f| f.header == "Strict-Transport-Security")
            .unwrap();
        assert!(f.note.contains("6 month"), "note was: {}", f.note);
        // 11 of 12 points: one warn drops A+ to A, it does not fail the site.
        assert_eq!(a.score_percent, 92);
        assert_eq!(a.grade, Grade::A);
    }

    #[test]
    fn hsts_max_age_zero_is_a_fail_because_it_switches_hsts_off() {
        let h: Headers = [("Strict-Transport-Security", "max-age=0")]
            .into_iter()
            .collect();
        let a = analyze(&h, true);
        assert_eq!(a.level_of("Strict-Transport-Security"), Some(Level::Fail));
    }

    #[test]
    fn hsts_long_but_without_include_subdomains_is_a_warn() {
        let h: Headers = [("Strict-Transport-Security", "max-age=31536000")]
            .into_iter()
            .collect();
        let a = analyze(&h, true);
        assert_eq!(a.level_of("Strict-Transport-Security"), Some(Level::Warn));
        let f = a
            .core
            .iter()
            .find(|f| f.header == "Strict-Transport-Security")
            .unwrap();
        assert!(f.note.contains("includeSubDomains"), "note: {}", f.note);
    }

    #[test]
    fn csp_with_unsafe_inline_scripts_is_a_warn_not_a_pass() {
        let h: Headers = [(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        )]
        .into_iter()
        .collect();
        let a = analyze(&h, true);
        assert_eq!(a.level_of("Content-Security-Policy"), Some(Level::Warn));
        let f = a
            .core
            .iter()
            .find(|f| f.header == "Content-Security-Policy")
            .unwrap();
        assert!(f.note.contains("unsafe-inline"), "note: {}", f.note);
        assert!(f.note.contains("unsafe-eval"), "note: {}", f.note);
    }

    #[test]
    fn csp_with_unsafe_inline_but_also_a_nonce_passes() {
        // Browsers that understand nonces ignore 'unsafe-inline' entirely,
        // so the pair is the documented backwards-compatibility recipe, not
        // a hole. Grading it as a warning would be a false positive.
        let h: Headers = [(
            "Content-Security-Policy",
            "script-src 'nonce-r4nd0m' 'unsafe-inline' 'self'",
        )]
        .into_iter()
        .collect();
        assert_eq!(
            analyze(&h, true).level_of("Content-Security-Policy"),
            Some(Level::Pass)
        );
    }

    #[test]
    fn csp_without_default_src_or_script_src_does_not_count_as_protection() {
        let h: Headers = [(
            "Content-Security-Policy",
            "img-src 'self'; style-src 'self'",
        )]
        .into_iter()
        .collect();
        let a = analyze(&h, true);
        assert_eq!(a.level_of("Content-Security-Policy"), Some(Level::Warn));
    }

    #[test]
    fn report_only_csp_is_a_warn_because_it_enforces_nothing() {
        let h: Headers = [(
            "Content-Security-Policy-Report-Only",
            "default-src 'self'; report-uri /csp",
        )]
        .into_iter()
        .collect();
        let a = analyze(&h, true);
        assert_eq!(a.level_of("Content-Security-Policy"), Some(Level::Warn));
    }

    #[test]
    fn csp_frame_ancestors_counts_as_x_frame_options() {
        let h: Headers = [("Content-Security-Policy", "frame-ancestors 'none'")]
            .into_iter()
            .collect();
        let a = analyze(&h, true);
        assert_eq!(a.level_of("X-Frame-Options"), Some(Level::Pass));
        let f = a
            .core
            .iter()
            .find(|f| f.header == "X-Frame-Options")
            .unwrap();
        assert_eq!(f.value.as_deref(), Some("CSP frame-ancestors 'none'"));
    }

    #[test]
    fn frame_ancestors_wildcard_is_not_protection() {
        let h: Headers = [(
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors *",
        )]
        .into_iter()
        .collect();
        assert_eq!(
            analyze(&h, true).level_of("X-Frame-Options"),
            Some(Level::Warn)
        );
    }

    #[test]
    fn x_frame_options_allow_from_is_a_warn_because_no_browser_honours_it() {
        let h: Headers = [("X-Frame-Options", "ALLOW-FROM https://partner.example")]
            .into_iter()
            .collect();
        assert_eq!(
            analyze(&h, true).level_of("X-Frame-Options"),
            Some(Level::Warn)
        );
    }

    #[test]
    fn x_content_type_options_with_a_wrong_value_is_a_warn() {
        let h: Headers = [("X-Content-Type-Options", "sniff")].into_iter().collect();
        assert_eq!(
            analyze(&h, true).level_of("X-Content-Type-Options"),
            Some(Level::Warn)
        );
    }

    #[test]
    fn referrer_policy_uses_the_last_token_of_a_fallback_chain() {
        // github.com really sends this pair; the modern token is the one
        // that applies, so grading the first would wrongly downgrade it.
        let h: Headers = [(
            "Referrer-Policy",
            "origin-when-cross-origin, strict-origin-when-cross-origin",
        )]
        .into_iter()
        .collect();
        assert_eq!(
            analyze(&h, true).level_of("Referrer-Policy"),
            Some(Level::Pass)
        );

        let h: Headers = [("Referrer-Policy", "no-referrer, unsafe-url")]
            .into_iter()
            .collect();
        assert_eq!(
            analyze(&h, true).level_of("Referrer-Policy"),
            Some(Level::Fail)
        );
    }

    #[test]
    fn referrer_policy_no_referrer_when_downgrade_is_a_warn() {
        let h: Headers = [("Referrer-Policy", "no-referrer-when-downgrade")]
            .into_iter()
            .collect();
        assert_eq!(
            analyze(&h, true).level_of("Referrer-Policy"),
            Some(Level::Warn)
        );
    }

    #[test]
    fn legacy_feature_policy_does_not_count_as_permissions_policy() {
        let h: Headers = [("Feature-Policy", "geolocation 'none'")]
            .into_iter()
            .collect();
        assert_eq!(
            analyze(&h, true).level_of("Permissions-Policy"),
            Some(Level::Warn)
        );
    }

    // --- risk flags --------------------------------------------------------

    #[test]
    fn wildcard_cors_with_credentials_caps_an_otherwise_perfect_site_at_c() {
        let mut h = hardened();
        h.insert("Access-Control-Allow-Origin", "*");
        h.insert("Access-Control-Allow-Credentials", "true");
        let a = analyze(&h, true);
        // The six graded headers are still all perfect...
        assert_eq!(a.score_percent, 100);
        // ...but the CORS misconfiguration caps the grade anyway.
        assert_eq!(a.grade, Grade::C);
        let r = a
            .risks
            .iter()
            .find(|r| r.header == "Access-Control-Allow-Origin")
            .unwrap();
        assert_eq!(r.level, Level::Fail);
    }

    #[test]
    fn wildcard_cors_without_credentials_is_only_a_warn_and_just_blocks_a_plus() {
        let mut h = hardened();
        h.insert("Access-Control-Allow-Origin", "*");
        let a = analyze(&h, true);
        assert_eq!(a.score_percent, 100);
        assert_eq!(a.grade, Grade::A);
    }

    #[test]
    fn versioned_server_header_is_flagged_but_a_bare_product_name_is_not() {
        let mut h = hardened();
        h.insert("Server", "nginx/1.18.0 (Ubuntu)");
        assert!(analyze(&h, true).risks.iter().any(|r| r.header == "Server"));

        let mut h = hardened();
        h.insert("Server", "cloudflare");
        assert!(!analyze(&h, true).risks.iter().any(|r| r.header == "Server"));
    }

    #[test]
    fn x_powered_by_is_flagged_as_version_disclosure() {
        let mut h = hardened();
        h.insert("X-Powered-By", "PHP/7.4.3");
        let a = analyze(&h, true);
        assert!(a.risks.iter().any(|r| r.header == "X-Powered-By"));
        assert_eq!(
            a.grade,
            Grade::A,
            "a warn-level flag should block A+, not more"
        );
    }

    // --- parsers -----------------------------------------------------------

    #[test]
    fn hsts_parser_handles_case_order_and_quoting() {
        let p = parse_hsts("includesubdomains; MAX-AGE=\"31536000\"; PRELOAD");
        assert_eq!(p.max_age, Some(31_536_000));
        assert!(p.include_subdomains);
        assert!(p.preload);

        let p = parse_hsts("max-age=abc");
        assert_eq!(p.max_age, None);
    }

    #[test]
    fn csp_directive_lookup_is_exact_not_substring() {
        let csp = "default-src 'self'; script-src-elem 'self'; frame-ancestors 'none'";
        // `script-src-elem` must not satisfy a lookup for `script-src`.
        assert_eq!(csp_directive(csp, "script-src"), None);
        assert_eq!(csp_directive(csp, "script-src-elem"), Some("'self'"));
        assert_eq!(csp_directive(csp, "frame-ancestors"), Some("'none'"));
        // A valueless directive is present-with-empty-value, not absent.
        assert_eq!(
            csp_directive("upgrade-insecure-requests", "upgrade-insecure-requests"),
            Some("")
        );
    }

    #[test]
    fn grade_parsing_round_trips_and_rejects_nonsense() {
        for g in [
            Grade::APlus,
            Grade::A,
            Grade::B,
            Grade::C,
            Grade::D,
            Grade::E,
            Grade::F,
        ] {
            assert_eq!(Grade::parse(g.as_str()), Some(g));
        }
        assert_eq!(Grade::parse("a+"), Some(Grade::APlus));
        assert_eq!(Grade::parse("Z"), None);
        // Ordering is worst-to-best so `min` picks the worse grade.
        assert!(Grade::F < Grade::C && Grade::C < Grade::APlus);
    }
}
