
fun protect(view: android.view.View) {
    // ruleid:android_tapjacking
    view.setFilterTouchesWhenObscured(true)
}
