
fun hidden(v: android.view.View, show: Boolean) {
    // ruleid:android_kotlin_hiddenui
    v.visibility = View.GONE
    // ruleid:android_kotlin_hiddenui
    v.visibility = View.INVISIBLE
    // ruleid:android_kotlin_hiddenui
    v.visibility = if (show) View.GONE else View.VISIBLE
    // ok:android_kotlin_hiddenui
    v.visibility = View.VISIBLE
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
