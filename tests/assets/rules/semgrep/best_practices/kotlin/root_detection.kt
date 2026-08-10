
fun check(device: Device) {
    // ruleid:android_root_detection
    device.isRooted()
    // ruleid:android_root_detection
    device.isDeviceRooted()
    // ruleid:android_root_detection
    RootTools.isAccessGiven()
    // ruleid:android_root_detection
    buildTags.contains("test-keys")
}
