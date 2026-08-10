// ruleid:insecure_tls_version
SSLContext.getInstance("TLSv1");
// ruleid:insecure_tls_version
SSLContext.getInstance("TLSv1.1");
// ok:insecure_tls_version
SSLContext.getInstance("TLSv1.2");
// ok:insecure_tls_version
SSLContext.getInstance("TLSv1.3");

// ruleid:insecure_tls_version
socket.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.2"});
// ok:insecure_tls_version
socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});

// ruleid:weak_tls_cipher_suite
socket.setEnabledCipherSuites(
    new String[] {"TLS_RSA_WITH_3DES_EDE_CBC_SHA"});
// ruleid:weak_tls_cipher_suite
socket.setEnabledCipherSuites(
    new String[] {"TLS_RSA_WITH_RC4_128_MD5"});
// ok:weak_tls_cipher_suite
socket.setEnabledCipherSuites(
    new String[] {"TLS_AES_128_GCM_SHA256"});
