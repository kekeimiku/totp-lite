RFC 6238: TOTP: Time-Based One-Time Password Algorithm

support sha256/sha512

```rust
let totp = TOTP::new(Secret::new(), "MY-PC", "user@localhost");
let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
totp.generate(timestamp);
println!("{}", totp.get_url());
println!("{}", totp.verify("you code", timestamp));
```