//! Two-tier, panic-free parsing of Combined Log Format lines.
//!
//! Example line:
//! `127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326`
//!
//! Tier 1: plain `str` splitting (no regex engine, no allocation).
//! Tier 2: a regex that tolerates oddities tier 1 is strict about.
//! Neither tier indexes a slice or calls `unwrap`, so neither can panic:
//! every failure is a `None`, propagated with `?`.

use std::sync::OnceLock;

use regex::Regex;

/// The fields we extract from one log line.
///
/// LIFETIME: `'a` ties every `&str` here to the *line it was parsed from*.
/// Nothing is copied while parsing; the borrow checker guarantees a
/// `ParsedLine` can never outlive its source `String`. Allocation happens
/// only later, in `Metrics`, and only the first time a key is seen.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedLine<'a> {
    pub ip: &'a str,
    pub method: &'a str,
    pub endpoint: &'a str,
    pub status: u16,
    /// True when tier 1 failed and the regex rescued the line.
    pub via_fallback: bool,
}

/// Parse a line: fast path, then regex fallback, else `None` (malformed).
pub fn parse_line(line: &str) -> Option<ParsedLine<'_>> {
    parse_fast(line).or_else(|| parse_regex(line))
}

fn valid_ip(ip: &str) -> bool {
    // IPv4 / IPv6 characters only. Rejects stray quotes, brackets, etc.
    !ip.is_empty() && ip.bytes().all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b':')
}

fn valid_status(s: &str) -> Option<u16> {
    let code: u16 = s.parse().ok()?;
    (100..=599).contains(&code).then_some(code)
}

/// Tier 1: strict, allocation-free splitting.
fn parse_fast(line: &str) -> Option<ParsedLine<'_>> {
    // "IP rest..."
    let (ip, rest) = line.split_once(' ')?;
    if !valid_ip(ip) {
        return None;
    }
    // Skip "ident user [timestamp]" by jumping to the opening quote of the
    // request: `] "`.
    let (_, after_ts) = rest.split_once("] \"")?;
    // request = `GET /index.html HTTP/1.0`, tail = ` 200 2326 ...`
    let (request, tail) = after_ts.split_once('"')?;

    // Exactly three space-separated parts, otherwise let the regex decide.
    let mut parts = request.split(' ');
    let method = parts.next()?;
    let endpoint = parts.next()?;
    let _protocol = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) || endpoint.is_empty() {
        return None;
    }

    let status_str = tail.strip_prefix(' ')?.split(' ').next()?;
    let status = valid_status(status_str)?;

    Some(ParsedLine { ip, method, endpoint, status, via_fallback: false })
}

/// The regex is compiled exactly once per process, lazily, and shared by all
/// rayon threads. `OnceLock` gives thread-safe one-time init; `Regex` is
/// `Sync` and uses an internal pool for its scratch space, so concurrent
/// `captures` calls need no external lock.
fn line_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"^([0-9A-Fa-f:.]+)\s+\S+\s+\S+\s+\[[^\]]*\]\s+"([A-Z]+)\s+(\S+)(?:\s+[^"]*)?"\s+(\d{3})\b"#,
        )
        // The pattern is a compile-time constant; a failure here is a
        // programmer error, not bad input, so failing loudly is correct.
        .expect("static regex is valid")
    })
}

/// Tier 2: slower but more forgiving (extra whitespace, HTTP/0.9 requests
/// with no protocol, trailing junk after the quote, ...).
fn parse_regex(line: &str) -> Option<ParsedLine<'_>> {
    let caps = line_regex().captures(line)?;
    // `Match<'h>::as_str` returns `&'h str`, borrowing from `line`, not from
    // `caps`, so the returned slices stay valid after `caps` is dropped.
    let status = valid_status(caps.get(4)?.as_str())?;
    Some(ParsedLine {
        ip: caps.get(1)?.as_str(),
        method: caps.get(2)?.as_str(),
        endpoint: caps.get(3)?.as_str(),
        status,
        via_fallback: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326"#;

    #[test]
    fn fast_path_parses_standard_line() {
        let p = parse_line(GOOD).unwrap();
        assert_eq!((p.ip, p.method, p.endpoint, p.status), ("127.0.0.1", "GET", "/index.html", 200));
        assert!(!p.via_fallback);
    }

    #[test]
    fn combined_format_with_referrer_and_agent() {
        let l = format!(r#"{GOOD} "http://ref/" "Mozilla/5.0 (X11)""#);
        assert_eq!(parse_line(&l).unwrap().status, 200);
    }

    #[test]
    fn regex_rescues_http09_request() {
        let l = r#"10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /old" 404 12"#;
        let p = parse_line(l).unwrap();
        assert!(p.via_fallback);
        assert_eq!((p.endpoint, p.status), ("/old", 404));
    }

    #[test]
    fn regex_rescues_extra_whitespace() {
        let l = r#"::1  -  - [10/Oct/2000:13:55:36 -0700]  "POST /api HTTP/1.1"  500 0"#;
        let p = parse_line(l).unwrap();
        assert!(p.via_fallback);
        assert_eq!((p.ip, p.method, p.status), ("::1", "POST", 500));
    }

    #[test]
    fn garbage_is_none_never_panics() {
        for l in [
            "", " ", "\"", "]\"", "a", "1.2.3.4", "1.2.3.4 - - [x] \"", "1.2.3.4 - - [x] \"GET /",
            "1.2.3.4 - - [x] \"GET / HTTP/1.1\" 999 1", "1.2.3.4 - - [x] \"GET / HTTP/1.1\" abc",
            "héllo wörld ✓ \u{0} \u{fffd}", "\"] \"\"] \"",
        ] {
            assert!(parse_line(l).is_none(), "should be malformed: {l:?}");
        }
    }

    #[test]
    fn multibyte_input_is_safe() {
        let l = "1.2.3.4 - - [é] \"GET /ü/✓ HTTP/1.1\" 200 5";
        assert_eq!(parse_line(l).unwrap().endpoint, "/ü/✓");
    }
}
