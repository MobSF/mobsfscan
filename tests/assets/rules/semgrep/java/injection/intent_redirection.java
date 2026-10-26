class IntentSamples {
    protected void onReceive(Context context, Intent intent) {
        Intent target = (Intent) intent.getParcelableExtra("extra_intent");
        // ruleid:android_intent_redirection
        context.startService(target);
    }
}
