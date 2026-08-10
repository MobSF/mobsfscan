class UnsafeCallback extends BiometricPrompt.AuthenticationCallback {
    // ruleid:android_biometric_without_crypto
    @Override
    public void onAuthenticationSucceeded(
            BiometricPrompt.AuthenticationResult result) {
        unlockAccount();
    }
}

class SafeCallback extends BiometricPrompt.AuthenticationCallback {
    // ok:android_biometric_without_crypto
    @Override
    public void onAuthenticationSucceeded(
            BiometricPrompt.AuthenticationResult result) {
        BiometricPrompt.CryptoObject crypto = result.getCryptoObject();
        decryptAccount(crypto.getCipher());
    }
}
