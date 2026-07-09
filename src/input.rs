//! Input container detection and re-wrapping.
//!
//! Files can hold raw BER/DER, a PEM block, bare base64 or hex text. The
//! detected container is remembered so that saving writes the file back in
//! the same outer format.

use crate::ber;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Container {
    Raw,
    Pem { label: String },
    Base64,
    Hex,
}

impl Container {
    pub fn describe(&self) -> String {
        match self {
            Container::Raw => "raw DER/BER".to_string(),
            Container::Pem { label } => format!("PEM ({})", label),
            Container::Base64 => "base64".to_string(),
            Container::Hex => "hex text".to_string(),
        }
    }
}

/// Detect the container format and return the decoded BER/DER bytes.
pub fn load(raw: &[u8]) -> Result<(Vec<u8>, Container), String> {
    if let Ok(text) = std::str::from_utf8(raw) {
        if text.contains("-----BEGIN ") {
            return load_pem(text);
        }
    }
    if ber::parse_forest(raw, 0).is_ok() {
        return Ok((raw.to_vec(), Container::Raw));
    }
    if let Ok(text) = std::str::from_utf8(raw) {
        let stripped: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if !stripped.is_empty() && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(bytes) = hex_decode(&stripped) {
                if ber::parse_forest(&bytes, 0).is_ok() {
                    return Ok((bytes, Container::Hex));
                }
            }
        }
        if let Ok(bytes) = b64_decode(&stripped) {
            if ber::parse_forest(&bytes, 0).is_ok() {
                return Ok((bytes, Container::Base64));
            }
        }
    }
    Err("input is not recognizable BER/DER, PEM, hex or base64".to_string())
}

fn load_pem(text: &str) -> Result<(Vec<u8>, Container), String> {
    let begin = text
        .find("-----BEGIN ")
        .ok_or("missing PEM BEGIN marker")?;
    let after_begin = &text[begin + "-----BEGIN ".len()..];
    let label_end = after_begin
        .find("-----")
        .ok_or("malformed PEM BEGIN marker")?;
    let label = after_begin[..label_end].to_string();
    let body_start = label_end + "-----".len();
    let end_marker = format!("-----END {}-----", label);
    let body_end = after_begin
        .find(&end_marker)
        .ok_or("missing PEM END marker")?;
    let body: String = after_begin[body_start..body_end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let bytes = b64_decode(&body)?;
    Ok((bytes, Container::Pem { label }))
}

/// Re-apply the outer container to freshly encoded DER bytes.
pub fn wrap(der: &[u8], container: &Container) -> Vec<u8> {
    match container {
        Container::Raw => der.to_vec(),
        Container::Pem { label } => {
            let mut out = format!("-----BEGIN {}-----\n", label);
            let b64 = b64_encode(der);
            for chunk in b64.as_bytes().chunks(64) {
                out.push_str(std::str::from_utf8(chunk).unwrap());
                out.push('\n');
            }
            out.push_str(&format!("-----END {}-----\n", label));
            out.into_bytes()
        }
        Container::Base64 => {
            let mut out = b64_encode(der);
            out.push('\n');
            out.into_bytes()
        }
        Container::Hex => {
            let mut out: String = der.iter().map(|b| format!("{:02x}", b)).collect();
            out.push('\n');
            out.into_bytes()
        }
    }
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex digits".to_string());
    }
    let digit = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("invalid hex digit '{}'", c as char)),
        }
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Ok(digit(p[0])? << 4 | digit(p[1])?))
        .collect()
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64_ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64_ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let val = |c: u8| -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 character '{}'", c as char)),
        }
    };
    let stripped = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(stripped.len() * 3 / 4);
    for chunk in stripped.as_bytes().chunks(4) {
        if chunk.len() == 1 {
            return Err("truncated base64 input".to_string());
        }
        let mut n: u32 = 0;
        for &c in chunk {
            n = n << 6 | val(c)?;
        }
        n <<= 6 * (4 - chunk.len()) as u32;
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DER: &[u8] = &[0x30, 0x05, 0x02, 0x01, 0x02, 0x05, 0x00];

    #[test]
    fn base64_roundtrip() {
        for len in 0..20 {
            let data: Vec<u8> = (0..len as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&data)).unwrap(), data);
        }
    }

    #[test]
    fn detects_raw() {
        let (bytes, c) = load(DER).unwrap();
        assert_eq!(bytes, DER);
        assert_eq!(c, Container::Raw);
    }

    #[test]
    fn detects_hex() {
        let (bytes, c) = load(b"3005 0201 02 0500\n").unwrap();
        assert_eq!(bytes, DER);
        assert_eq!(c, Container::Hex);
    }

    #[test]
    fn detects_base64() {
        let text = b64_encode(DER);
        let (bytes, c) = load(text.as_bytes()).unwrap();
        assert_eq!(bytes, DER);
        assert_eq!(c, Container::Base64);
    }

    #[test]
    fn pem_roundtrip() {
        let pem = wrap(DER, &Container::Pem { label: "CERTIFICATE".to_string() });
        let (bytes, c) = load(&pem).unwrap();
        assert_eq!(bytes, DER);
        assert_eq!(c, Container::Pem { label: "CERTIFICATE".to_string() });
        assert_eq!(wrap(&bytes, &c), pem);
    }
}
