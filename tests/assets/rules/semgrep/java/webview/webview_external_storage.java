// ruleid:webview_external_storage
String path = Environment.getExternalStorageDirectory().toString() + "/Download/income_tax_return.pdf";
mWebView.loadUrl( "file:///android_asset/pdfjs/web/viewer.html?file=" + path);
mWebView.loadUrl(path);

mWebView.loadUrl( path + "file:///android_asset/pdfjs/web/viewer.html?file=");


mWebView.loadUrl(Environment.getExternalStorageDirectory() + "/doo");


// ruleid:webview_external_storage
engine.loadUrl("file:///" + Environment.getExternalStorageDirectory().getPath() + "testing.html");


// ruleid:webview_external_storage
engine.loadUrl("file:///"+Environment.getExternalStorageDirectory().getAbsolutePath() + "testing.html");