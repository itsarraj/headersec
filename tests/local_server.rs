//! End-to-end tests against a real HTTP server, bound to loopback and
//! started by the test itself. These go through the actual HTTP client and
//! the actual header-collection path — they just don't need the internet,
//! so they run in normal `cargo test` and on a restricted CI runner.
//!
//! The internet-facing tests live in `tests/live.rs` and are `#[ignore]`d.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use headersec::fetch::fetch;
use headersec::grade::{analyze, Grade, Level};

/// Starts a one-shot HTTP/1.1 server on a loopback port that answers every
/// request with `200 OK` plus exactly `extra_headers`, then returns its URL.
/// `serves` is how many requests to answer before the thread exits.
fn serve(extra_headers: &'static str, serves: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        for _ in 0..serves {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            handle(stream, extra_headers);
        }
    });

    format!("http://127.0.0.1:{port}/")
}

fn handle(mut stream: TcpStream, extra_headers: &str) {
    // Drain the request head so the client isn't writing into a closed pipe.
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }

    let body = "<!doctype html><title>t</title>";
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         {extra_headers}\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn timeout() -> Duration {
    Duration::from_secs(10)
}

#[test]
fn a_server_that_sends_no_security_headers_at_all_grades_f() {
    // The guaranteed-bad case: a real socket, a real HTTP response, and
    // deliberately none of the headers this tool looks for.
    let url = serve("", 1);
    let f = fetch(&url, timeout(), true).expect("fetch from loopback server");

    assert_eq!(f.status, 200);
    assert!(!f.https, "loopback server is plain HTTP");
    assert!(
        f.redirected_from.is_none(),
        "nothing redirected, so nothing should be reported as a redirect"
    );
    // It really did answer — we have headers, just not security ones.
    assert!(f.headers.has("content-type"));

    let a = analyze(&f.headers, f.https);
    assert_eq!(a.grade, Grade::F, "assessment was {a:?}");
    assert_eq!(a.level_of("Content-Security-Policy"), Some(Level::Fail));
    assert_eq!(a.level_of("X-Content-Type-Options"), Some(Level::Fail));
    assert_eq!(a.level_of("X-Frame-Options"), Some(Level::Fail));
    // Plain HTTP, so HSTS is excluded rather than scored as a failure.
    assert_eq!(
        a.level_of("Strict-Transport-Security"),
        Some(Level::NotApplicable)
    );
}

#[test]
fn the_same_server_with_a_hardened_header_set_grades_a_plus() {
    // Identical transport, identical code path, only the headers differ —
    // which is what makes this a real contrast rather than two unrelated
    // sites happening to score differently.
    let url = serve(
        "Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none'\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: strict-origin-when-cross-origin\r\n\
         Permissions-Policy: geolocation=(), camera=(), microphone=()\r\n",
        1,
    );
    let f = fetch(&url, timeout(), true).expect("fetch from loopback server");
    let a = analyze(&f.headers, f.https);

    // HSTS is N/A over plain HTTP, so the other five carry the score.
    assert_eq!(a.score_percent, 100, "{a:?}");
    assert_eq!(a.grade, Grade::APlus, "{a:?}");
    assert_eq!(
        a.core
            .iter()
            .find(|c| c.header == "Content-Security-Policy")
            .and_then(|c| c.value.clone())
            .as_deref(),
        Some("default-src 'self'; script-src 'self'; frame-ancestors 'none'"),
        "the raw header value must survive the round trip verbatim"
    );
}

#[test]
fn a_dangerous_cors_pair_on_a_real_response_is_flagged_and_caps_the_grade() {
    let url = serve(
        "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Permissions-Policy: camera=()\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Credentials: true\r\n\
         X-Powered-By: Express\r\n",
        1,
    );
    let f = fetch(&url, timeout(), true).expect("fetch from loopback server");
    let a = analyze(&f.headers, f.https);

    assert_eq!(a.score_percent, 100, "every graded header is present");
    assert_eq!(a.grade, Grade::C, "the CORS pair must cap the grade");
    assert!(a
        .risks
        .iter()
        .any(|r| r.header == "Access-Control-Allow-Origin" && r.level == Level::Fail));
    assert!(a.risks.iter().any(|r| r.header == "X-Powered-By"));
}

#[test]
fn a_port_with_nothing_listening_is_a_clean_error_not_a_panic_or_a_hang() {
    // Bind and immediately drop, so the port is known-closed.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let err = fetch(
        &format!("http://127.0.0.1:{port}/"),
        Duration::from_secs(3),
        true,
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&format!("127.0.0.1:{port}")),
        "error should name the target: {msg}"
    );
}
