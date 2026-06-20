use anyhow::Result;
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;

const SEARCH_URL: &str = "https://html.duckduckgo.com/html/";
/// Hard cap on results returned.
const MAX_RESULTS: usize = 5;

#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub title: String,
    pub snippet: String,
    pub url: String,
}

/// Read-only DuckDuckGo HTML search. No API key, no tracking, no writes.
pub async fn web_search(query: &str, max_results: usize) -> Result<Vec<SearchResult>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (compatible; Legion-ARES/0.1; threat-intel-enrichment)")
        .build()?;

    let resp = client.get(SEARCH_URL).query(&[("q", query)]).send().await?;

    if !resp.status().is_success() {
        anyhow::bail!("DuckDuckGo search returned {}", resp.status());
    }

    let html = resp.text().await?;
    Ok(parse_results(&html, max_results.min(MAX_RESULTS)))
}

fn parse_results(html: &str, max: usize) -> Vec<SearchResult> {
    let mut results: Vec<SearchResult> = Vec::new();
    let mut pos = 0;

    while results.len() < max {
        // Locate the next result link
        let Some(rel) = html[pos..].find("class=\"result__a\"") else {
            break;
        };
        pos += rel;

        // Extract href
        let Some(href_pos) = html[pos..].find("href=\"") else {
            break;
        };
        let after_href = pos + href_pos + 6;
        let Some(href_end_rel) = html[after_href..].find('"') else {
            break;
        };
        let raw_url = &html[after_href..after_href + href_end_rel];

        // Extract title (text between > and </a>)
        let Some(gt_pos) = html[pos..].find('>') else {
            break;
        };
        let after_gt = pos + gt_pos + 1;
        let Some(close_pos) = html[after_gt..].find("</a>") else {
            break;
        };
        let title = strip_tags(&html[after_gt..after_gt + close_pos])
            .trim()
            .to_string();
        pos = after_gt + close_pos + 4;

        // Extract snippet within the next 2 KB
        let window_end = (pos + 2048).min(html.len());
        let snippet = extract_snippet(&html[pos..window_end]);

        let url = decode_url(raw_url);
        if !url.is_empty() && !title.is_empty() {
            results.push(SearchResult {
                title,
                snippet,
                url,
            });
        }
    }

    results
}

fn extract_snippet(window: &str) -> String {
    if let Some(s) = window.find("result__snippet") {
        let after = &window[s..];
        if let Some(gt) = after.find('>') {
            let content = &after[gt + 1..];
            if let Some(end) = content.find("</") {
                return strip_tags(&content[..end]).trim().to_string();
            }
        }
    }
    String::new()
}

fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&nbsp;", " ")
}

fn decode_url(raw: &str) -> String {
    // DDG wraps links in /l/?uddg=... redirect; extract the real URL.
    let decoded = if let Some(idx) = raw.find("uddg=") {
        let after = &raw[idx + 5..];
        let end = after.find('&').unwrap_or(after.len());
        percent_decode(&after[..end])
    } else {
        raw.to_string()
    };
    if decoded.starts_with("http://") || decoded.starts_with("https://") {
        decoded
    } else {
        String::new()
    }
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut bytes = s.bytes().peekable();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let h1 = bytes.next().unwrap_or(b'0');
            let h2 = bytes.next().unwrap_or(b'0');
            let hex = [h1, h2];
            if let Ok(hex_str) = std::str::from_utf8(&hex) {
                if let Ok(byte) = u8::from_str_radix(hex_str, 16) {
                    out.push(byte as char);
                    continue;
                }
            }
        } else if b == b'+' {
            out.push(' ');
            continue;
        }
        out.push(b as char);
    }
    out
}

#[doc(hidden)]
pub fn parse_results_for_testing(html: &str, max: usize) -> Vec<SearchResult> {
    parse_results(html, max)
}
