package com.mobsfscan.fixtures;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;
import android.net.LocalServerSocket;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.webkit.WebView;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import net.openid.appauth.AuthorizationRequest;

public class JavaNewRules {

    // android_provider_path_traversal
    public ParcelFileDescriptor openFile(Uri uri, String mode)
            throws FileNotFoundException {
        File file = new File(getContext().getFilesDir(), uri.getLastPathSegment());
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    // android_zip_slip
    public void unzip(String zipPath, String destDir) throws Exception {
        byte[] buffer = new byte[1024];
        ZipInputStream zis = new ZipInputStream(new FileInputStream(zipPath));
        ZipEntry entry = zis.getNextEntry();
        while (entry != null) {
            File newFile = new File(destDir, entry.getName());
            FileOutputStream fos = new FileOutputStream(newFile);
            fos.close();
            entry = zis.getNextEntry();
        }
    }

    // android_intent_redirection
    protected void onReceive(Context context, Intent intent) {
        Intent target = (Intent) intent.getParcelableExtra("extra_intent");
        context.startService(target);
    }

    // android_pending_intent_not_immutable
    public void schedule(Context context) {
        Intent intent = new Intent("com.example.app.ACTION_SYNC");
        PendingIntent pendingIntent = PendingIntent.getBroadcast(
                context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);
    }

    // android_deeplink_to_webview
    protected void onCreate(Bundle bundle) {
        Uri data = getIntent().getData();
        WebView webView = new WebView(this);
        webView.loadUrl(data.toString());
    }

    protected void openUrl(WebView webView) {
        webView.loadUrl(getIntent().getData().toString());
    }

    // android_local_server_socket
    public void startSocket() throws Exception {
        LocalServerSocket server = new LocalServerSocket("com.example.app.rpc");
    }

    // android_db_on_external_storage
    public void openDb(Context context) {
        String path = context.getExternalFilesDir(null).getPath() + "/app.db";
        SQLiteDatabase.openOrCreateDatabase(path, null);
    }

    // android_oauth_custom_scheme_redirect
    public void authorize() {
        AuthorizationRequest.Builder builder = new AuthorizationRequest.Builder(
                mAuthConfig, CLIENT_ID, "code", mRedirectUri);
        builder.setRedirectUri(Uri.parse("com.example.app:/oauth2redirect"));
    }

    // google_api_key
    private static final String MAPS_API_KEY = "AIza12345678901234567890123456789012345";

    // private_key_pem
    private static final String SIGNING_KEY =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----";
}
