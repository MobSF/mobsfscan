fun attest(context: android.content.Context) {
    // ruleid:android_safetynet
    SafetyNet.getClient(context)
}

// ruleid:android_safetynet
val api = "com.google.android.gms.safetynet.SafetyNetApi"
