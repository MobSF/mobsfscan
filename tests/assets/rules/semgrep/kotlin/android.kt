
fun hidden(passwordView: android.view.View, headerDivider: android.view.View, show: Boolean) {
    // ruleid:android_kotlin_hiddenui
    passwordView.visibility = View.GONE
    // ruleid:android_kotlin_hiddenui
    passwordView.visibility = View.INVISIBLE
    // ruleid:android_kotlin_hiddenui
    passwordView.visibility = if (show) View.GONE else View.VISIBLE
    // ruleid:android_kotlin_hiddenui
    passwordView.setVisibility(View.GONE)
    // ok:android_kotlin_hiddenui
    passwordView.visibility = View.VISIBLE
    // ok:android_kotlin_hiddenui
    headerDivider.visibility = View.GONE
    // ok:android_kotlin_hiddenui
    headerDivider.setVisibility(View.INVISIBLE)
}

fun logging() {
    // ruleid:android_kotlin_logging
    Log.e("t", "m")
    // ruleid:android_kotlin_logging
    System.out.println("x")
}

fun secrets() {
    // ruleid:android_kotlin_hardcoded
    val password = "secret"
    // ruleid:android_kotlin_hardcoded
    val key = "abcd"
    // ok:android_kotlin_hardcoded
    val accountName = "alice"
}

fun storage(ctx: android.content.Context) {
    // ruleid:android_kotlin_world_readable
    ctx.getSharedPreferences("a", Context.MODE_WORLD_READABLE)
    // ruleid:android_kotlin_world_writable
    ctx.getSharedPreferences("a", Context.MODE_WORLD_WRITEABLE)
    // ruleid:android_kotlin_world_writable
    ctx.openFileOutput("a", 2)
    // ruleid:android_kotlin_world_read_write
    ctx.openFileOutput("a", 3)
}

fun input(passwordField: android.widget.EditText, emailField: android.widget.EditText) {
    // ruleid:android_kotlin_sensitive_input_keyboard_cache
    passwordField.inputType = InputType.TYPE_CLASS_TEXT
    // ok:android_kotlin_sensitive_input_keyboard_cache
    passwordField.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    // ok:android_kotlin_sensitive_input_keyboard_cache
    emailField.inputType = InputType.TYPE_CLASS_TEXT
}

fun notify(builder: androidx.core.app.NotificationCompat.Builder, oneTimePassword: String, accountName: String) {
    // ruleid:android_kotlin_sensitive_notification
    builder.setContentText(oneTimePassword)
    // ok:android_kotlin_sensitive_notification
    builder.setContentTitle(accountName)
}

fun badPending(context: Context, intent: Intent) {
    // ruleid:android_kotlin_pending_intent_not_immutable
    PendingIntent.getBroadcast(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)
    val flags = PendingIntent.FLAG_UPDATE_CURRENT
    // ruleid:android_kotlin_pending_intent_not_immutable
    PendingIntent.getBroadcast(context, 0, intent, flags)
}

fun goodPending(context: Context, intent: Intent) {
    // ok:android_kotlin_pending_intent_not_immutable
    PendingIntent.getBroadcast(
        context, 0, intent,
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    // ok:android_kotlin_pending_intent_not_immutable
    PendingIntent.getBroadcast(context, 0, intent, flags)
    var sdkFlags = PendingIntent.FLAG_UPDATE_CURRENT
    if (Build.VERSION.SDK_INT >= 23) {
        sdkFlags = sdkFlags or PendingIntent.FLAG_IMMUTABLE
    }
    // ok:android_kotlin_pending_intent_not_immutable
    PendingIntent.getBroadcast(context, 0, intent, sdkFlags)
}

fun badUnrelatedIf(context: Context, intent: Intent, immutableRequested: Boolean) {
    var flags = PendingIntent.FLAG_UPDATE_CURRENT
    if (immutableRequested) {
        flags = flags or PendingIntent.FLAG_IMMUTABLE
    }
    // ruleid:android_kotlin_pending_intent_not_immutable
    PendingIntent.getBroadcast(context, 0, intent, flags)
}

fun externalDb(context: Context) {
    // ruleid:android_kotlin_db_on_external_storage
    val path = context.getExternalFilesDir(null)!!.path + "/app.db"
    SQLiteDatabase.openOrCreateDatabase(path, null)
    // ruleid:android_kotlin_db_on_external_storage
    val env = Environment.getExternalStorageDirectory().absolutePath + "/app.db"
    SQLiteDatabase.openOrCreateDatabase(env, null)
    // ruleid:android_kotlin_db_on_external_storage
    val db = File(context.getExternalFilesDir(null), "app.db")
    SQLiteDatabase.openOrCreateDatabase(db.absolutePath, null)
    // ok:android_kotlin_db_on_external_storage
    SQLiteDatabase.openOrCreateDatabase("app.db", null)
    // ruleid:android_kotlin_db_on_external_storage
    val publicPath = Environment.getExternalStoragePublicDirectory(
        Environment.DIRECTORY_DOWNLOADS).path + "/app.db"
    SQLiteDatabase.openDatabase(publicPath, null, SQLiteDatabase.OPEN_READWRITE)
}

// ruleid:android_kotlin_db_on_external_storage
class Helper(context: Context) : SQLiteOpenHelper(
    context,
    Environment.getExternalStorageDirectory().absolutePath + "/app.db",
    null,
    1,
)

// ok:android_kotlin_db_on_external_storage
class InternalHelper(context: Context) : SQLiteOpenHelper(context, "app.db", null, 1)

fun authorize(builder: AuthorizationRequest.Builder) {
    // ruleid:android_kotlin_oauth_custom_scheme_redirect
    builder.setRedirectUri(Uri.parse("my-app://callback"))
    // ok:android_kotlin_oauth_custom_scheme_redirect
    builder.setRedirectUri(Uri.parse("https://example.com/oauth"))
    // ruleid:android_kotlin_oauth_custom_scheme_redirect
    val custom = "my-app://callback"
    builder.setRedirectUri(Uri.parse(custom))
    val https = "https://example.com/oauth"
    // ok:android_kotlin_oauth_custom_scheme_redirect
    builder.setRedirectUri(Uri.parse(https))
}
