import Foundation

NSLog("bol suppressed")  // mobsf-ignore: ios_log
    NSLog("indented suppressed")  // mobsf-ignore: ios_log
    NSLog("still reported")
    os_log("also reported")
