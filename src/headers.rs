/// A case-insensitive, order-preserving view of a set of HTTP response
/// headers.
///
/// This exists so the grading logic in `grade.rs` never touches the HTTP
/// client's own types: every rule can be unit-tested against a header set
/// constructed by hand, with no socket involved. `fetch.rs` is the only
/// place that converts a real response into one of these.
///
/// Header names are stored lowercased (HTTP field names are
/// case-insensitive; HTTP/2 requires them lowercased on the wire anyway),
/// values verbatim apart from surrounding whitespace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a header. Repeats are kept rather than overwritten — a
    /// response is genuinely allowed to send `Content-Security-Policy`
    /// more than once, and silently dropping one would misreport what the
    /// server actually sent.
    pub fn insert(&mut self, name: &str, value: &str) {
        self.entries
            .push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }

    /// The first value sent for `name`, or `None` if the header is absent.
    pub fn get(&self, name: &str) -> Option<&str> {
        let want = name.to_ascii_lowercase();
        self.entries
            .iter()
            .find(|(k, _)| *k == want)
            .map(|(_, v)| v.as_str())
    }

    /// Every value sent for `name`, in wire order.
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let want = name.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|(k, _)| *k == want)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

impl<K: AsRef<str>, V: AsRef<str>> FromIterator<(K, V)> for Headers {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut h = Headers::new();
        for (k, v) in iter {
            h.insert(k.as_ref(), v.as_ref());
        }
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_case_insensitive_in_both_directions() {
        let h: Headers = [("X-Frame-Options", "DENY")].into_iter().collect();
        assert_eq!(h.get("x-frame-options"), Some("DENY"));
        assert_eq!(h.get("X-FRAME-OPTIONS"), Some("DENY"));
        assert_eq!(h.get("X-Frame-Options"), Some("DENY"));
    }

    #[test]
    fn values_are_trimmed_but_not_otherwise_altered() {
        let h: Headers = [("Referrer-Policy", "  strict-origin-when-cross-origin ")]
            .into_iter()
            .collect();
        assert_eq!(
            h.get("referrer-policy"),
            Some("strict-origin-when-cross-origin")
        );
    }

    #[test]
    fn repeated_headers_are_all_kept() {
        let h: Headers = [
            ("Content-Security-Policy", "default-src 'self'"),
            ("Content-Security-Policy", "frame-ancestors 'none'"),
        ]
        .into_iter()
        .collect();
        assert_eq!(h.get_all("content-security-policy").len(), 2);
        // `get` is first-wins, matching "which policy do I show".
        assert_eq!(h.get("content-security-policy"), Some("default-src 'self'"));
    }

    #[test]
    fn missing_header_is_none_not_empty_string() {
        let h = Headers::new();
        assert_eq!(h.get("content-security-policy"), None);
        assert!(!h.has("content-security-policy"));
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
    }
}
