
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.SslErrorHandler
import android.net.http.SslError

fun web(wv: WebView) {
    // ruleid:android_kotlin_webview
    wv.addJavascriptInterface(Any(), "bridge")
    // ruleid:android_kotlin_webview_allow_file_from_url
    wv.settings.allowFileAccessFromFileURLs = true
    // ruleid:android_kotlin_webview_debug
    WebView.setWebContentsDebuggingEnabled(true)
    // ruleid:android_kotlin_webview_mixed_content
    wv.settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
    // ruleid:android_kotlin_webview_external
    wv.loadUrl(Environment.getExternalStorageDirectory().absolutePath)
}

class InsecureClient : WebViewClient() {
    // ruleid:android_kotlin_webview_ignore_ssl
    override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
        handler.proceed()
    }
}

fun fileAccess(settings: WebSettings) {
    // ruleid:android_kotlin_webview_set_allow_file_access
    settings.allowFileAccess = true
    // ruleid:android_kotlin_webview_set_allow_file_access
    settings.setAllowFileAccess(true)
    // ok:android_kotlin_webview_set_allow_file_access
    settings.allowFileAccess = false
}

