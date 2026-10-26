class DeepLinkSamples {
    protected void onCreate(Bundle bundle) {
        Uri data = getIntent().getData();
        WebView webView = new WebView(this);
        // ruleid:android_deeplink_to_webview
        webView.loadUrl(data.toString());
    }

    protected void openUrl(WebView webView) {
        // ruleid:android_deeplink_to_webview
        webView.loadUrl(getIntent().getData().toString());
    }

    protected void dataString(WebView webView) {
        // ruleid:android_deeplink_to_webview
        webView.loadUrl(getIntent().getDataString());
    }

    protected void allowedHost(WebView webView) {
        Uri data = getIntent().getData();
        if (data != null && "example.com".equals(data.getHost())) {
            // ok:android_deeplink_to_webview
            webView.loadUrl(data.toString());
        }
    }
}
