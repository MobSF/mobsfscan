export function BadHandlers() {
  const onMessage = (ev) => {
    console.log(ev.nativeEvent.url);
    handle(ev.nativeEvent.data);
  };
  const onMessagePresenceIf = (ev) => {
    if (ev.nativeEvent.url) {
      handle(ev.nativeEvent.data);
    }
  };
  const handleMessagePresenceReturn = (ev) => {
    if (!ev.nativeEvent.url) return;
    handle(ev.nativeEvent.data);
  };
  const onMessageSubstringBypass = (ev) => {
    if (ev.nativeEvent.url.includes("trusted.example.com")) {
      handle(ev.nativeEvent.data);
    }
  };
  const onMessageUnboundedPrefixBypass = (ev) => {
    if (!ev.nativeEvent.url.startsWith("https://trusted.example.com")) return;
    handle(ev.nativeEvent.data);
  };
  return (
    <>
      <WebView onMessage={(e) => run(e.nativeEvent.data)} />
      <WebView onMessage={(e) => { if (e.nativeEvent.url) { run(e.nativeEvent.data); } }} />
      <WebView onMessage={(e) => { if (!e.nativeEvent.url) return; run(e.nativeEvent.data); }} />
      <WebView onMessage={(e) => { if (e.nativeEvent.url.includes("trusted.example.com")) { run(e.nativeEvent.data); } }} />
    </>
  );
}
export function GoodHandlers() {
  const onMessage = (ev) => {
    if (ev.nativeEvent.url !== "https://trusted.example.com") {
      return;
    }
    handle(ev.nativeEvent.data);
  };
  const handleWebViewMessage = (ev) => {
    if (new URL(ev.nativeEvent.url).origin === TRUSTED_ORIGIN) {
      handle(ev.nativeEvent.data);
    }
  };
  const onBridgeMessage = (ev) => {
    const { url } = ev.nativeEvent;
    if (!url.startsWith("https://trusted.example.com/")) return;
    handle(ev.nativeEvent.data);
  };
  const onAllowlistOrigin = (ev) => {
    if (!ALLOWED_ORIGINS.has(new URL(ev.nativeEvent.url).origin)) return;
    handle(ev.nativeEvent.data);
  };
  const onScroll = (ev) => track(ev.nativeEvent.data);
  return (
    <Camera onBarCodeRead={(e) => scan(e.nativeEvent.data)} />
  );
}
