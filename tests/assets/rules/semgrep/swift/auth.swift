
func auth(ctx: LAContext) {
    // ruleid:ios_biometric_bool
    ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock") { _, _ in }
}
// ruleid:ios_biometric_acl
_ = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlocked, .biometryAny, nil)
// ruleid:ios_keychain_weak_acl_device_passcode
_ = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlocked, .devicePasscode, nil)
// ruleid:ios_keychain_weak_accessibility_value
_ = kSecAttrAccessibleAlways

func startAuth(url: URL) {
    // ruleid:ios_oauth_callback_custom_scheme
    let session = ASWebAuthenticationSession(url: url, callbackURLScheme: "my-app") { _, _ in }
    // ok:ios_oauth_callback_custom_scheme
    let https = ASWebAuthenticationSession(url: url, callbackURLScheme: "https") { _, _ in }
}
