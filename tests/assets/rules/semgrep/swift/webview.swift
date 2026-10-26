
func load(webView: WKWebView, html: String) {
    // ruleid:ios_load_html_string
    webView.loadHTMLString(html, baseURL: nil)
}
// ruleid:ios_uiwebview
let legacy = UIWebView()

func setupBridge(webView: WKWebView) {
    // ruleid:ios_wkwebview_script_message_handler
    webView.configuration.userContentController.add(self, name: "bridge")
}
