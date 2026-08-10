
fun random() {
    // ruleid:android_kotlin_insecure_random
    val r = Random()
}

fun ciphers() {
    // ruleid:android_kotlin_aes_ecb
    Cipher.getInstance("AES/ECB/NoPadding")
    // ruleid:android_kotlin_aes_ecb_default
    Cipher.getInstance("AES")
    // ruleid:cbc_kotlin_padding_oracle
    Cipher.getInstance("AES/CBC/PKCS5Padding")
    // ruleid:android_kotlin_rsa_no_oaep
    Cipher.getInstance("RSA/ECB/NoPadding")
    // ruleid:android_kotlin_weak_ciphers
    Cipher.getInstance("DES")
    // ok:android_kotlin_aes_ecb
    Cipher.getInstance("AES/GCM/NoPadding")
}

fun hashes() {
    // ruleid:android_kotlin_md5
    MessageDigest.getInstance("MD5")
    // ruleid:android_kotlin_sha1
    MessageDigest.getInstance("SHA-1")
    // ruleid:android_kotlin_weak_hash
    MessageDigest.getInstance("MD4")
}

fun iv() {
    // ruleid:android_kotlin_weak_iv
    val weak = byteArrayOf(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
}

// ruleid:android_kotlin_custom_xor_crypto
fun encryptXor(a: Int, b: Int): Int {
    return a xor b
}

// ok:android_kotlin_custom_xor_crypto
fun toggle(a: Int, b: Int) = a xor b

fun hardcodedKey(cipher: Cipher) {
    // ruleid:android_kotlin_aes_hardcoded_key
    val secret = SecretKeySpec("hardcoded".toByteArray(), "AES")
    cipher.init(Cipher.ENCRYPT_MODE, secret)

    // ok:android_kotlin_aes_hardcoded_key
    val dynamic = SecretKeySpec(password.toByteArray(), "AES")
    cipher.init(Cipher.ENCRYPT_MODE, dynamic)
}

fun staticIv(strKey: String, plainText: String) {
    // ruleid:android_kotlin_cbc_static_iv
    val bytesIV = "foo".toByteArray()
    val iv = IvParameterSpec(bytesIV)
    val skeySpec = SecretKeySpec(strKey.toByteArray(), "AES")
    // ruleid:cbc_kotlin_padding_oracle
    val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv)
}

fun sslv3() {
    // ruleid:android_kotlin_insecure_sslv3
    SSLContext.getInstance("SSLv3")
    // ok:android_kotlin_insecure_sslv3
    SSLContext.getInstance("TLSv1.3")
}

fun weakKeys() {
    // ruleid:android_kotlin_weak_key_size
    val kp = KeyPairGenerator.getInstance("RSA")
    kp.initialize(512)

    // ruleid:android_kotlin_weak_key_size
    val kg = KeyGenerator.getInstance("AES")
    kg.init(64)

    // ok:android_kotlin_weak_key_size
    val strong = KeyPairGenerator.getInstance("RSA")
    strong.initialize(4096)
}

