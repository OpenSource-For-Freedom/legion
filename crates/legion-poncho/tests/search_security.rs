use legion_poncho::search::parse_results_for_testing;

#[test]
fn search_results_reject_non_http_url_schemes() {
    let html = r#"
      <a class="result__a" href="javascript:alert(1)">Bad</a>
      <a class="result__a" href="/l/?uddg=data%3Atext%2Fhtml%2Cbad">Data</a>
      <a class="result__a" href="/l/?uddg=https%3A%2F%2Fexample.com%2Fsafe">Safe</a>
    "#;

    let results = parse_results_for_testing(html, 5);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://example.com/safe");
    assert_eq!(results[0].title, "Safe");
}
