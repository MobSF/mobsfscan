
// ruleid:ios_file_no_special
let opts: Data.WritingOptions = .noFileProtection
// ruleid:ios_general_paste
_ = UIPasteboard.generalPasteboard

func extract(archive: String, dest: String) {
    // ruleid:ios_ssziparchive_unzip
    SSZipArchive.unzipFile(atPath: archive, toDestination: dest)
    // ruleid:ios_ssziparchive_unzip
    SSZipArchive.unzipFile(atPath: archive, toDestination: dest, delegate: self)
    // ruleid:ios_ssziparchive_unzip
    SSZipArchive.unzipFile(
        atPath: archive,
        toDestination: dest,
        progressHandler: { _, _ in },
        completionHandler: { _, _ in })
}
