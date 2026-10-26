// Fragments in separate messages must not match.
- (void)unrelated:(NSString *)archive dest:(NSString *)dest {
    [Extractor unzipFileAtPath:archive];
    [Writer write:payload toDestination:dest];
}
