
func disable(field: UITextField) {
    // ruleid:ios_keyboard_cache
    field.autocorrectionType = .no
}
func blockKeyboard() {
    // ruleid:ios_custom_keyboard_disabled
    if extensionPointIdentifier == UIExtensionPointIdentifier.keyboard {}
}
