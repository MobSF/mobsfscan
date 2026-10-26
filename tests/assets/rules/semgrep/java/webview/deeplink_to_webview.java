class DeepLinkSamples {
    // ruleid:android_deeplink_to_webview
    protected void onCreate(Bundle bundle) {
        Uri data = getIntent().getData();
        WebView webView = new WebView(this);
        webView.loadUrl(data.toString());
    }

    // ruleid:android_deeplink_to_webview
    protected void openUrl(WebView webView) {
        webView.loadUrl(getIntent().getData().toString());
    }
}
