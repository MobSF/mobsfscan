import { WebView } from "react-native-webview";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { MMKV } from "react-native-mmkv";
import { Linking } from "react-native";
const API_KEY = "sk_live_9876543210abcdef123456";
const store = new MMKV();
export function Screen({ deepLink, html, isPremium }) {
  if (!isPremium) { return null; }
  const keyName = "auth_token";
  AsyncStorage.setItem(keyName, API_KEY);
  Linking.openURL(deepLink);
  frame.contentWindow.postMessage(API_KEY, "*");
  if (__DEV__) { console.log("dev secret:", API_KEY); }
  console.log("prod secret_token:", API_KEY);
  const onMsg = (ev) => JSON.parse(ev.nativeEvent.data);
  fetch("http://api.insecure.example.com/v1");
  return (
    <WebView
      javaScriptEnabled={true}
      allowUniversalAccessFromFileURLs={true}
      mixedContentMode="always"
      originWhitelist={["*"]}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
