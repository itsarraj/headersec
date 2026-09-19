use std::time::Duration;

use clap::Parser;
use headersec::fetch::{self};
use headersec::grade::{analyze, Grade};
use headersec::report;

#[derive(Parser)]
#[command(
    name = "headersec",
    about = "Grade a live URL's HTTP response security headers",
    long_about = "Fetches a URL and grades the security headers on the response it actually \
                  serves: Content-Security-Policy, Strict-Transport-Security, \
                  X-Content-Type-Options, X-Frame-Options (or CSP frame-ancestors), \
                  Referrer-Policy and Permissions-Policy — plus risk flags for dangerous \
                  headers that are present."
)]
struct Cli {
    /// URLs to check. A bare hostname is assumed to be https://.
    urls: Vec<String>,

    /// Request timeout in seconds.
    #[arg(long, default_value_t = 15)]
    timeout: u64,

    /// Exit non-zero if any URL grades below this (A+, A, B, C, D, E, F).
    #[arg(long, default_value = "B")]
    min_grade: String,

    /// Grade the first response instead of following redirects. Useful for
    /// checking what an http:// entry point itself sends.
    #[arg(long)]
    no_redirect: bool,

    /// Machine-readable output (one JSON array for all URLs).
    #[arg(long)]
    json: bool,

    /// Print full header values instead of truncating long ones.
    #[arg(long)]
    full: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.urls.is_empty() {
        anyhow::bail!("no URLs given — try `headersec example.com`");
    }
    let min_grade = Grade::parse(&cli.min_grade).ok_or_else(|| {
        anyhow::anyhow!(
            "unrecognised --min-grade {:?} (expected one of A+, A, B, C, D, E, F)",
            cli.min_grade
        )
    })?;

    let timeout = Duration::from_secs(cli.timeout);
    let mut below_threshold = false;
    let mut errored = false;
    let mut json_out = Vec::new();

    for (i, url) in cli.urls.iter().enumerate() {
        match fetch::fetch(url, timeout, !cli.no_redirect) {
            Ok(f) => {
                let assessment = analyze(&f.headers, f.https);
                if assessment.grade < min_grade {
                    below_threshold = true;
                }
                if cli.json {
                    json_out.push(report::render_json(&f, &assessment));
                } else {
                    if i > 0 {
                        println!();
                    }
                    print!("{}", report::render_text(&f, &assessment, cli.full));
                }
            }
            Err(e) => {
                errored = true;
                if cli.json {
                    json_out.push(serde_json::json!({
                        "url": fetch::normalize_url(url),
                        "error": format!("{e:#}"),
                    }));
                } else {
                    // Print to stderr so a failed target can't be mistaken
                    // for a graded one in piped output. The error chain
                    // already names the URL it was requesting.
                    eprintln!("ERROR  {e:#}");
                }
            }
        }
    }

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&json_out)?);
    }

    if errored || below_threshold {
        std::process::exit(1);
    }
    Ok(())
}
