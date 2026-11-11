# L5 shared rustls fork

Base: rustls 0.23.46, upstream commit f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb.
Branch: codex/l5-0.23.46.

The source is migrated from the identical l5droid and l5proxy-rust vendored copies.
Retains 16 KiB ordinary read sizing, reusable deframer storage with cursor-based discard,
external receive-buffer processing, private record type 0x7e, and control-output notification.

Both consumers enable l5-experimental; only the server additionally enables
l5-openssl-serverhello. This changes ServerHello extension order only and does not
claim full OpenSSL fingerprint equivalence. Normal handshake/control records retain TLS protection.
Private payload records do not provide outer TLS integrity; L5 command protection and
payload encryption policy are implemented separately in l5-rust-wire and its consumers.

After committing and pushing this branch, both consumers should pin the same Git revision
in [patch.crates-io], including the transitive rustls dependency of tokio-rustls.
Do not move consumers to the upstream 0.24 development branch during this migration.
