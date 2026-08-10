
fun protect(window: android.view.Window) {
    // ruleid:android_prevent_screenshot
    window.setFlags(
        WindowManager.LayoutParams.FLAG_SECURE,
        WindowManager.LayoutParams.FLAG_SECURE,
    )
    // ruleid:android_prevent_screenshot
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
}
