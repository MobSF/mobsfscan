print("Salt used: \(self.salt)\n")
NSLog("Salt used: %@", self.salt)
os_log("network request started")

// Should not match ios_hardcoded_secret (#111)
private static let APP_VERSION_KEY = "AppVersionStringKey"
private static let languageKey = "languageKey"
private let leadsLoggedKey = "leadsLogged_Key"

// Should match ios_hardcoded_secret
let password = "s3cret"
let key = "sk-live-abc123"
let api_key = "sk-live-abc123"
let secretKey = "abc"

// Should match ios_oauth_callback_custom_scheme
func startAuth(url: URL) {
    let session = ASWebAuthenticationSession(url: url, callbackURLScheme: "com.example.app") { callbackURL, error in
    }
}

func startAuthExplicit(url: URL) {
    let session = ASWebAuthenticationSession(
        url: url,
        callbackURLScheme: "com.example.app",
        completionHandler: { callbackURL, error in })
}

// Should match ios_ssziparchive_unzip
func extract(archive: String, dest: String) {
    SSZipArchive.unzipFile(atPath: archive, toDestination: dest)
    SSZipArchive.unzipFile(atPath: archive, toDestination: dest, overwrite: true, password: nil)
}
