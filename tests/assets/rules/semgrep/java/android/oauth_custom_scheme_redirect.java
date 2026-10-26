class OAuthSamples {
    void custom(AuthorizationRequest.Builder builder) {
        // ruleid:android_oauth_custom_scheme_redirect
        builder.setRedirectUri(Uri.parse("my-app://callback"));
        // ruleid:android_oauth_custom_scheme_redirect
        builder.setRedirectUri(Uri.parse("com.example.app:/oauth2redirect"));
    }

    void https(AuthorizationRequest.Builder builder) {
        // ok:android_oauth_custom_scheme_redirect
        builder.setRedirectUri(Uri.parse("https://example.com/oauth"));
    }

    void fromVariable(AuthorizationRequest.Builder builder) {
        // ruleid:android_oauth_custom_scheme_redirect
        String custom = "my-app://callback";
        builder.setRedirectUri(Uri.parse(custom));
        String https = "https://example.com/oauth";
        // ok:android_oauth_custom_scheme_redirect
        builder.setRedirectUri(Uri.parse(https));
    }
}
