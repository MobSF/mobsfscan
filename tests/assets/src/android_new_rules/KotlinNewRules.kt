package com.mobsfscan.fixtures

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.net.LocalServerSocket
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.webkit.WebView
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import net.openid.appauth.AuthorizationRequest

class KotlinNewRules {

    // android_kotlin_provider_path_traversal
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        val file = File(context.filesDir, uri.lastPathSegment)
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    // android_kotlin_zip_slip
    fun unzip(zipPath: String, destDir: String) {
        val zis = ZipInputStream(FileInputStream(zipPath))
        var entry: ZipEntry? = zis.nextEntry
        while (entry != null) {
            val newFile = File(destDir, entry.name)
            FileOutputStream(newFile).close()
            entry = zis.nextEntry
        }
    }

    // android_kotlin_intent_redirection
    fun onReceive(context: Context, intent: Intent) {
        val target = intent.getParcelableExtra<Intent>("extra_intent")
        context.startService(target)
    }

    // android_kotlin_pending_intent_not_immutable
    fun schedule(context: Context) {
        val intent = Intent("com.example.app.ACTION_SYNC")
        val pendingIntent = PendingIntent.getBroadcast(
            context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)
    }

    // android_kotlin_deeplink_to_webview
    fun onCreate(webView: WebView) {
        val data = intent.data
        webView.loadUrl(data.toString())
    }

    // android_kotlin_local_server_socket
    fun startSocket() {
        val server = LocalServerSocket("com.example.app.rpc")
    }

    // android_kotlin_db_on_external_storage
    fun openDb(context: Context) {
        val path = context.getExternalFilesDir(null)!!.path + "/app.db"
        SQLiteDatabase.openOrCreateDatabase(path, null)
    }

    // android_kotlin_oauth_custom_scheme_redirect
    fun authorize() {
        val builder = AuthorizationRequest.Builder(config, CLIENT_ID, "code", redirectUri)
        builder.setRedirectUri(Uri.parse("com.example.app:/oauth2redirect"))
    }
}
