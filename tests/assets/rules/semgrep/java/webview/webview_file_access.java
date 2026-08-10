class Webview extends WebViewClient {
        public void vulnerableMethodSetAllowFileAccess() {
                WebView web = (WebView) findViewById(R.id.webview);
        }
        public void vulnerableMethodSetAllowFileAccess2() {
                WebView web = (WebView) findViewById(R.id.webview);
                WebSettings webSettings = web.getSettings();
                webSettings.setWebContentsDebuggingEnabled(true);
                // ruleid:webview_set_allow_file_access
                webSettings.setAllowFileAccess(true);
        }

         public void vulnerableMethodSetAllowFileAccess1() {
                boolean fileAccess = true;
                WebView web = (WebView) findViewById(R.id.webview);
                WebSettings webSettings = web.getSettings();
                webSettings.setWebContentsDebuggingEnabled(true);
                // ruleid:webview_set_allow_file_access
                webSettings.setAllowFileAccess(fileAccess);
        }

          public void vulnerableMethodSetAllowFileAccessok() {
                boolean fileAccess = false;
                WebView web = (WebView) findViewById(R.id.webview);
                WebSettings webSettings = web.getSettings();
                webSettings.setWebContentsDebuggingEnabled(true);
                // ok: webview_set_allow_file_access
                webSettings.setAllowFileAccess(fileAccess);
        }
}
