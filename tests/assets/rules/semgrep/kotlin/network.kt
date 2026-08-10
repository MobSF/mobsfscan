
fun ssl(socket: javax.net.ssl.SSLSocket) {
    // ruleid:android_kotlin_insecure_ssl
    HttpsURLConnection.setDefaultHostnameVerifier(NullHostnameVerifier())
    // ruleid:android_kotlin_insecure_tls_version
    SSLContext.getInstance("TLSv1.1")
    // ok:android_kotlin_insecure_tls_version
    SSLContext.getInstance("TLSv1.2")
    // ruleid:android_kotlin_insecure_tls_version
    socket.setEnabledProtocols(arrayOf("TLSv1", "TLSv1.2"))
    // ruleid:android_kotlin_weak_tls_cipher_suite
    socket.setEnabledCipherSuites(arrayOf("TLS_RSA_WITH_RC4_128_MD5"))
    // ok:android_kotlin_weak_tls_cipher_suite
    socket.setEnabledCipherSuites(arrayOf("TLS_AES_128_GCM_SHA256"))
}
