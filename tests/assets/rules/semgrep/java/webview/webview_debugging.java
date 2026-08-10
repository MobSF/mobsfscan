package com.myapp;

import com.facebook.react.ReactActivity;
import android.webkit.WebView;

public class MainActivity extends ReactActivity {

    /**
     * Returns the name of the main component registered from JavaScript.
     * This is used to schedule rendering of the component.
     */
    @Override
    protected String getMainComponentName() {
        return "myapp";
    }

    @Override
    protected void onCreate() {
        super.onCreate();
        //added this line with necessary imports at the top.
        // ruleid:webview_debugging
        WebView.setWebContentsDebuggingEnabled(true);
    }
}