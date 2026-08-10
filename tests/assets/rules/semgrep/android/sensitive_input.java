void configureFields(EditText passwordField, EditText emailField) {
    // ruleid:android_sensitive_input_keyboard_cache
    passwordField.setInputType(InputType.TYPE_CLASS_TEXT);

    // ok:android_sensitive_input_keyboard_cache
    passwordField.setInputType(
        InputType.TYPE_CLASS_TEXT
            | InputType.TYPE_TEXT_VARIATION_PASSWORD);

    // ok:android_sensitive_input_keyboard_cache
    emailField.setInputType(
        InputType.TYPE_CLASS_TEXT
            | InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS);
}
