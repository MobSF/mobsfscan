import android.text.InputType
import javax.net.ssl.SSLContext

fun insecureTls() {
    SSLContext.getInstance("TLSv1.1")
}

fun weakSuite(socket: javax.net.ssl.SSLSocket) {
    socket.setEnabledCipherSuites(
        arrayOf("TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    )
}

fun configureInput(passwordField: android.widget.EditText) {
    passwordField.inputType = InputType.TYPE_CLASS_TEXT
}

fun encryptByte(value: Int, key: Int) = value xor key

fun notifySecret(
    builder: androidx.core.app.NotificationCompat.Builder,
    oneTimePassword: String,
) {
    builder.setContentText(oneTimePassword)
}
