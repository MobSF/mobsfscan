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
