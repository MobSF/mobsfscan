
func load(webView: WKWebView, html: String) {
    // ruleid:ios_load_html_string
    webView.loadHTMLString(html, baseURL: nil)
}
// ruleid:ios_uiwebview
let legacy = UIWebView()
