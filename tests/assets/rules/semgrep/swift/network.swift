
// ruleid:ios_tls3_not_used
session.TLSMinimumSupportedProtocolVersion = .TLSv10
// ruleid:ios_tls3_not_used
session.TLSMinimumSupportedProtocolVersion = tls_protocol_version_t.TLSv11
// ruleid:ios_tls12_used
session.TLSMinimumSupportedProtocolVersion = tls_protocol_version_t.TLSv12
// ruleid:ios_dtls1_used
session.TLSMinimumSupportedProtocolVersion = .DTLSv10
// ruleid:ios_depr_tls_min
session.tlsMinimumSupportedProtocol = .tlsProtocol12
