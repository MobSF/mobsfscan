byte[] encrypt(byte[] plaintext, byte key) {
    byte[] output = new byte[plaintext.length];
    for (int i = 0; i < plaintext.length; i++) {
        // ruleid:android_custom_xor_crypto
        output[i] = (byte) (plaintext[i] ^ key);
    }
    return output;
}

int toggleFlag(int flags, int mask) {
    // ok:android_custom_xor_crypto
    return flags ^ mask;
}

byte[] encrypt(byte[] plaintext, SecretKey key) {
    // ok:android_custom_xor_crypto
    return standardCipher.doFinal(plaintext);
}
