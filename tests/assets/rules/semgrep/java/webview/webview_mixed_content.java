package com.example;

import android.webkit.WebSettings;
import android.webkit.WebView;

public class MixedContentWebView {
    public void insecure(WebView webView) {
        WebSettings settings = webView.getSettings();
        // ruleid:webview_mixed_content
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
    }

    public void insecureCompatAlias(WebView webView) {
        // ruleid:webview_mixed_content
        webView.getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
    }

    public void safeNeverAllow(WebView webView) {
        // ok:webview_mixed_content
        webView.getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
    }

    public void safeCompatibility(WebView webView) {
        // ok:webview_mixed_content
        webView.getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);
    }
}
