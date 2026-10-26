class IntentSamples {
    protected void onReceive(Context context, Intent intent) {
        Intent target = (Intent) intent.getParcelableExtra("extra_intent");
        // ruleid:android_intent_redirection
        context.startService(target);
        // ruleid:android_intent_redirection
        startActivity(target);
        // ruleid:android_intent_redirection
        sendBroadcast(target);
        // ruleid:android_intent_redirection
        startActivityForResult(target, 1);
        // ok:android_intent_redirection
        startActivity(new Intent(context, NextActivity.class));
        // ok:android_intent_redirection
        startActivity(Intent.parseUri("intent://example.com/#Intent;end", 0));
        // ruleid:android_intent_redirection
        startActivity(Intent.parseUri(intent.getDataString(), 0));
    }
}
