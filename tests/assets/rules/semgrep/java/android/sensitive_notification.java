void buildNotifications(
        NotificationCompat.Builder builder,
        String oneTimePassword,
        String accountName) {
    // ruleid:android_sensitive_notification
    builder.setContentText(oneTimePassword);

    // ok:android_sensitive_notification
    builder.setContentTitle(accountName);

    // ok:android_sensitive_notification
    builder.setContentText("Open the app to continue");
}
