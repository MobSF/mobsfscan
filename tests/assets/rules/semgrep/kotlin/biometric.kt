
class UnsafeCallback : BiometricPrompt.AuthenticationCallback() {
    // ruleid:android_kotlin_biometric_without_crypto
    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        unlockAccount()
    }
}

class SafeCallback : BiometricPrompt.AuthenticationCallback() {
    // ok:android_kotlin_biometric_without_crypto
    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        val crypto = result.cryptoObject
        decryptAccount(crypto?.cipher)
    }
}
