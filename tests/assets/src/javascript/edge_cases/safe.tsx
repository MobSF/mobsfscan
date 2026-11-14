const w = <WebView allowFileAccess={false} />;
el.innerHTML = DOMPurify.sanitize(untrustedHtml);
el.innerHTML = sanitizeHtml(untrustedHtml);
el.innerHTML = goog.html.SafeHtml.unwrapTrustedHTML(h);
el.innerHTML = "<b>static</b>";
AsyncStorage.setItem("theme", "secret_dark_mode");
AsyncStorage.multiSet([["theme", "auth_token_value_only"]]);
fetch("http://localhost:8080/api");
const svgNs = "http://www.w3.org/2000/svg";
WebBrowser.openAuthSessionAsync("https://trusted.example.com/auth", redirectUri);
if (__DEV__) {
  Reactotron.configure({}).useReactNative().connect();
}
