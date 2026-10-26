  CC_MD5([hashMaterial bytes], (CC_LONG)[hashMaterial length], md);
// Should match ios_sszip_unzip
- (void)extractArchive:(NSString *)archivePath toDirectory:(NSString *)destPath {
    [SSZipArchive unzipFileAtPath:archivePath toDestination:destPath];
    [SSZipArchive unzipFileAtPath:archivePath
                    toDestination:destPath
                         delegate:self];
}
