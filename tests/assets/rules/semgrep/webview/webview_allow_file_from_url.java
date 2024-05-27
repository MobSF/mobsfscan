
package com.company.something;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

public class HelloWebApp extends Activity {
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        WebView webView = (WebView)findViewById(R.id.webView);
        String badUrl = getIntent().getStringExtra("URL");
        boolean x = true;
        WebSettings webSettings = webView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        // ruleid:webview_allow_file_from_url
        webSettings.setAllowFileAccessFromFileURLs(x);
        webView.setWebChromeClient(new WebChromeClient());
        webView.loadUrl(badUrl);
    }
}