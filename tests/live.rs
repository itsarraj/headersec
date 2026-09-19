//! Tests that hit the real internet. Every one is `#[ignore]`d so a
//! restricted CI runner (or an offline checkout) still passes a plain
//! `cargo test`; run them deliberately with:
//!
//! ```text
//! cargo test --test live -- --ignored --nocapture
//! ```
//!
//! These assert on properties that are true of a well-run site in general
//! (HSTS exists, the grade is at least a B) rather than on exact header
//! values, which real sites change without warning. The exact values
//! observed at the time of writing are quoted in the README instead.

use std::time::Duration;

use headersec::fetch::fetch;
use headersec::grade::{analyze, Grade, Level};

fn timeout() -> Duration {
    Duration::from_secs(20)
}

#[test]
#[ignore = "hits the real internet"]
fn github_com_scores_well_and_really_does_send_hsts() {
    let f = fetch("github.com", timeout(), true).expect("fetch github.com");
    assert!(f.https);
    assert_eq!(f.status, 200);

    let a = analyze(&f.headers, f.https);
    println!("{}", headersec::report::render_text(&f, &a, false));

    assert!(
        a.grade >= Grade::B,
        "github.com should grade at least B, got {} ({}%)",
        a.grade.as_str(),
        a.score_percent
    );
    assert_eq!(a.level_of("Strict-Transport-Security"), Some(Level::Pass));
    assert_eq!(a.level_of("X-Content-Type-Options"), Some(Level::Pass));
    assert_eq!(a.level_of("Content-Security-Policy"), Some(Level::Pass));
}

#[test]
#[ignore = "hits the real internet"]
fn example_com_is_a_real_site_that_genuinely_sends_none_of_these() {
    // A real, live, non-toy origin serving HTTPS with no security headers
    // at all — the contrast case for github.com.
    let f = fetch("example.com", timeout(), true).expect("fetch example.com");
    assert!(f.https);

    let a = analyze(&f.headers, f.https);
    println!("{}", headersec::report::render_text(&f, &a, false));

    assert_eq!(a.grade, Grade::F, "expected F, got {}", a.grade.as_str());
    assert_eq!(a.level_of("Strict-Transport-Security"), Some(Level::Fail));
    // ...and the HTTPS-without-HSTS condition is raised as a risk flag.
    assert!(a
        .risks
        .iter()
        .any(|r| r.header == "Strict-Transport-Security" && r.level == Level::Fail));
}

#[test]
#[ignore = "hits the real internet"]
fn httpbin_org_really_does_serve_the_dangerous_cors_pair() {
    // A live endpoint that genuinely sends `Access-Control-Allow-Origin: *`
    // together with `Access-Control-Allow-Credentials: true` — the flag
    // this tool exists to raise, verified against a real server rather
    // than only a fixture.
    let f = fetch("httpbin.org", timeout(), true).expect("fetch httpbin.org");
    let a = analyze(&f.headers, f.https);
    println!("{}", headersec::report::render_text(&f, &a, false));

    assert_eq!(f.headers.get("access-control-allow-origin"), Some("*"));
    assert_eq!(
        f.headers.get("access-control-allow-credentials"),
        Some("true")
    );
    assert!(a
        .risks
        .iter()
        .any(|r| r.header == "Access-Control-Allow-Origin" && r.level == Level::Fail));
    // And its versioned `Server` header is flagged, while github's bare
    // `Server: github.com` is not.
    assert!(a.risks.iter().any(|r| r.header == "Server"));
}

#[test]
#[ignore = "hits the real internet"]
fn a_plain_http_only_site_has_hsts_excluded_rather_than_failed() {
    // info.cern.ch is still served over plain HTTP. Grading HSTS as a
    // failure there would be meaningless — browsers ignore the header on
    // an http:// response entirely.
    let f = fetch("http://info.cern.ch/", timeout(), true).expect("fetch info.cern.ch");
    assert!(!f.https, "expected this host to still be http-only");

    let a = analyze(&f.headers, f.https);
    println!("{}", headersec::report::render_text(&f, &a, false));
    assert_eq!(
        a.level_of("Strict-Transport-Security"),
        Some(Level::NotApplicable)
    );
}

#[test]
#[ignore = "hits the real internet"]
fn redirects_are_followed_so_the_graded_response_is_the_real_page() {
    // stripe.com answers / with a 307 to a localised path. Grading the
    // redirect itself rather than its destination is the classic way to
    // report the wrong header set.
    let followed = fetch("https://stripe.com/", timeout(), true).expect("fetch stripe.com");
    assert_eq!(followed.status, 200);
    assert!(
        followed.redirected_from.is_some(),
        "expected a redirect from https://stripe.com/, landed on {}",
        followed.final_url
    );

    let unfollowed =
        fetch("https://stripe.com/", timeout(), false).expect("fetch stripe.com, no redirect");
    assert!(
        (300..400).contains(&unfollowed.status),
        "--no-redirect should surface the {} itself",
        unfollowed.status
    );
    assert!(unfollowed.headers.has("location"));
}
