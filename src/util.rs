pub fn parse_demical_or_hex(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let mut n = 0;
    let prefix = &s[0..=1];
    if prefix == "0x" {
        let hex_str = &s[2..];
        // hex::decodeは偶数個の数字文字でないとパースしてくれないのでこうしている
        let hex_string = if hex_str.len() % 2 == 0 {
            String::from(hex_str)
        } else {
            ["0", hex_str].concat()
        };
        let addr_decoded = hex::decode(hex_string)?;
        for (i, d) in addr_decoded.iter().enumerate() {
            n += (*d as u64) << ((addr_decoded.len() - 1 - i) * 8);
        }
    } else {
        n = s.parse::<u64>()?;
    }
    Ok(n)
}
