# totp-lite

totp-lite 是rust的一个轻量 [TOTP](https://en.wikipedia.org/wiki/Time-based_one-time_password) 实现，支持 sha256/sha512
```rust
let secret = "AZKXE3W57Q53ESFUWY4TKEAXIGLC7STL".as_bytes();
// let secret: Vec<u8> = repeat_with(|| fastrand::u8(..)).take(20).collect();

let totp = TOTP::with_default(secret, "MY-PC", "user@localhost");
let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
let url = totp.get_url();
println!("{}", url);
println!("{}", totp.verify("input you code", timestamp));

// let qrcode = fast_qr::QRBuilder::new(url).build().unwrap();
// let _svg = SvgBuilder::default().shape(Shape::RoundedSquare).to_file(&qrcode, "out.svg");
```
旨在与其它crates配合使用，而不需要强制下载几十个根本用不上的crates

## 极简主义
最小设计，牢记[UNIX 精神](https://en.wikipedia.org/wiki/Unix_philosophy#Do_One_Thing_and_Do_It_Well)，做一件事，并将其做好。
