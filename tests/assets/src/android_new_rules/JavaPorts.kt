
import android.hardware.biometrics.BiometricPrompt
import android.webkit.WebSettings
import java.beans.XMLDecoder
import java.io.InputStream
import java.io.ObjectInputStream
import java.security.KeyPairGenerator
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLContext
import javax.xml.stream.XMLInputFactory

class UnsafeBio : BiometricPrompt.AuthenticationCallback() {
    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        unlockAccount()
    }
}

fun hardcodedAes(cipher: Cipher) {
    val secret = SecretKeySpec("hardcoded".toByteArray(), "AES")
    cipher.init(Cipher.ENCRYPT_MODE, secret)
}

fun staticCbcIv(key: String) {
    val bytesIV = "static-iv-value".toByteArray()
    val iv = IvParameterSpec(bytesIV)
    Cipher.getInstance("AES/CBC/PKCS5PADDING")
}

fun legacySsl() {
    SSLContext.getInstance("SSLv3")
}

fun weakRsa() {
    val kp = KeyPairGenerator.getInstance("RSA")
    kp.initialize(512)
}

fun allowFiles(settings: WebSettings) {
    settings.allowFileAccess = true
}

fun runCommand(user: String) {
    Runtime.getRuntime().exec("id " + user)
}

fun deserialize(stream: InputStream): Any {
    return ObjectInputStream(stream).readObject()
}

fun openXml(): XMLInputFactory {
    val factory = XMLInputFactory.newFactory()
    return factory
}

fun enableXxe(factory: XMLInputFactory) {
    factory.setProperty("javax.xml.stream.isSupportingExternalEntities", true)
}

fun decodeXml(stream: InputStream): Any {
    return XMLDecoder(stream).readObject()
}

private fun unlockAccount() {}
