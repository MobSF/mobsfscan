
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
        webView.getSettings().setJavaScriptEnabled(true);
        // ruleid:webview_javascript_interface
        webView.addJavascriptInterface(new testClass(), "jsinterface");
        webView.loadUrl("file:///android_asset/www/index.html");
    }
}