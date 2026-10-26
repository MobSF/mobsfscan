class PendingIntentSamples {
    void badInline(Context context, Intent intent) {
        // ruleid:android_pending_intent_not_immutable
        PendingIntent.getBroadcast(
            context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);
    }

    void badZero(Context context, Intent intent) {
        // ruleid:android_pending_intent_not_immutable
        PendingIntent.getActivity(context, 0, intent, 0);
    }

    void badMutable(Context context, Intent intent) {
        // ruleid:android_pending_intent_not_immutable
        PendingIntent.getService(context, 0, intent, PendingIntent.FLAG_MUTABLE);
    }

    void badVar(Context context, Intent intent) {
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        // ruleid:android_pending_intent_not_immutable
        PendingIntent.getBroadcast(context, 0, intent, flags);
    }

    void goodInline(Context context, Intent intent) {
        // ok:android_pending_intent_not_immutable
        PendingIntent.getBroadcast(
            context,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    void goodVar(Context context, Intent intent) {
        int flags = PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT;
        // ok:android_pending_intent_not_immutable
        PendingIntent.getBroadcast(context, 0, intent, flags);
    }

    void goodOrAssign(Context context, Intent intent) {
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        flags |= PendingIntent.FLAG_IMMUTABLE;
        // ok:android_pending_intent_not_immutable
        PendingIntent.getForegroundService(context, 0, intent, flags);
    }

    void goodIf(Context context, Intent intent) {
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        // ok:android_pending_intent_not_immutable
        PendingIntent.getBroadcast(context, 0, intent, flags);
    }

    void goodBare(Context context, Intent intent) {
        int flags = FLAG_IMMUTABLE | FLAG_UPDATE_CURRENT;
        // ok:android_pending_intent_not_immutable
        PendingIntent.getBroadcast(context, 0, intent, flags);
    }
}
