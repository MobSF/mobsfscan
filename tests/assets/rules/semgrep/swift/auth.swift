
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
