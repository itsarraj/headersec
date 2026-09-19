//! Rendering. Kept out of `main.rs` so the text and JSON shapes are
//! testable and so `grade.rs` stays free of any formatting concern.

use crate::fetch::Fetched;
use crate::grade::{Assessment, Level};

/// Truncates on a char boundary so a multi-byte CSP never panics the
/// formatter.
fn shorten(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{}…", kept.trim_end())
}

const VALUE_WIDTH: usize = 96;

pub fn render_text(fetched: &Fetched, a: &Assessment, full: bool) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "{}  [{}]  grade {}  ({}%)\n",
        fetched.final_url,
        fetched.status,
        a.grade.as_str(),
        a.score_percent
    ));
    if let Some(from) = &fetched.redirected_from {
        out.push_str(&format!(
            "  followed a redirect from {from} — the headers below are the final response's\n"
        ));
    }
    out.push('\n');

    for f in &a.core {
        out.push_str(&format!("  {}  {}\n", f.level.label(), f.header));
        if let Some(v) = &f.value {
            let shown = if full {
                v.clone()
            } else {
                shorten(v, VALUE_WIDTH)
            };
            out.push_str(&format!("        {shown}\n"));
        }
        if f.level != Level::Pass || f.value.is_none() {
            out.push_str(&format!("        {}\n", f.note));
        }
        out.push('\n');
    }

    if a.risks.is_empty() {
        out.push_str("  no risk flags\n");
    } else {
        out.push_str("  risk flags\n");
        for r in &a.risks {
            out.push_str(&format!("    {}  {}\n", r.level.label(), r.header));
            if let Some(v) = &r.value {
                let shown = if full {
                    v.clone()
                } else {
                    shorten(v, VALUE_WIDTH)
                };
                out.push_str(&format!("          {shown}\n"));
            }
            out.push_str(&format!("          {}\n", r.note));
        }
    }

    out
}

fn finding_json(f: &crate::grade::Finding) -> serde_json::Value {
    serde_json::json!({
        "header": f.header,
        "level": f.level.label().trim().to_ascii_lowercase(),
        "value": f.value,
        "note": f.note,
    })
}

pub fn render_json(fetched: &Fetched, a: &Assessment) -> serde_json::Value {
    serde_json::json!({
        "url": fetched.final_url,
        "requested_url": fetched.redirected_from,
        "status": fetched.status,
        "https": fetched.https,
        "grade": a.grade.as_str(),
        "score_percent": a.score_percent,
        "headers": a.core.iter().map(finding_json).collect::<Vec<_>>(),
        "risks": a.risks.iter().map(finding_json).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grade::analyze;
    use crate::headers::Headers;

    fn fetched(url: &str, https: bool) -> Fetched {
        Fetched {
            final_url: url.to_string(),
            status: 200,
            https,
            headers: Headers::new(),
            redirected_from: None,
        }
    }

    #[test]
    fn text_report_names_every_graded_header_and_the_grade() {
        let a = analyze(&Headers::new(), true);
        let text = render_text(&fetched("https://a.test/", true), &a, false);
        for h in [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ] {
            assert!(text.contains(h), "report omitted {h}:\n{text}");
        }
        assert!(text.contains("grade F"), "{text}");
        assert!(text.contains("risk flags"), "{text}");
    }

    #[test]
    fn long_values_are_truncated_on_a_char_boundary_unless_full() {
        // A real CSP is far longer than the column; a multi-byte character
        // straddling the cut would panic a byte-slice implementation.
        let csp = format!("default-src 'self'; report-uri /{}é", "x".repeat(200));
        let h: Headers = [("Content-Security-Policy", csp.as_str())]
            .into_iter()
            .collect();
        let a = analyze(&h, true);
        let short = render_text(&fetched("https://a.test/", true), &a, false);
        assert!(short.contains('…'));
        assert!(!short.contains(&csp));

        let long = render_text(&fetched("https://a.test/", true), &a, true);
        assert!(long.contains(&csp));
    }

    #[test]
    fn json_report_is_machine_readable_and_keeps_raw_values() {
        let h: Headers = [("X-Content-Type-Options", "nosniff")]
            .into_iter()
            .collect();
        let a = analyze(&h, true);
        let v = render_json(&fetched("https://a.test/", true), &a);
        // One pass and two warns out of six graded headers.
        assert_eq!(v["grade"], "E");
        assert_eq!(v["score_percent"], 34);
        assert_eq!(v["status"], 200);
        assert_eq!(v["https"], true);
        let xcto = v["headers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["header"] == "X-Content-Type-Options")
            .unwrap()
            .clone();
        assert_eq!(xcto["level"], "pass");
        assert_eq!(xcto["value"], "nosniff");
        // A missing header is null, not the empty string.
        let csp = v["headers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["header"] == "Content-Security-Policy")
            .unwrap()
            .clone();
        assert!(csp["value"].is_null());
    }

    #[test]
    fn a_redirect_is_stated_in_the_report_rather_than_hidden() {
        let mut f = fetched("https://example.test/in", true);
        f.redirected_from = Some("https://example.test".to_string());
        let text = render_text(&f, &analyze(&Headers::new(), true), false);
        assert!(
            text.contains("followed a redirect from https://example.test"),
            "{text}"
        );
    }
}
