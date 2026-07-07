/// Wrapper Zstd per la compressione dei payload CyberSheppard.

use anyhow::Result;
use serde::Serialize;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CompressedPayload {
    pub original_size: usize,
    pub compressed_size: usize,
    pub compression_ratio: f64,
    /// Dati compressi in base64
    pub data: String,
}

/// Serializza `value` come JSON, comprime con Zstd al `level` indicato
/// e restituisce un `CompressedPayload` pronto per l'invio.
pub fn compress_json<T: Serialize>(value: &T, level: i32) -> Result<CompressedPayload> {
    let json = serde_json::to_vec(value)?;
    let original_size = json.len();

    let compressed = zstd::encode_all(json.as_slice(), level)?;
    let compressed_size = compressed.len();

    let compression_ratio = if original_size > 0 {
        (1.0 - compressed_size as f64 / original_size as f64) * 100.0
    } else {
        0.0
    };

    Ok(CompressedPayload {
        original_size,
        compressed_size,
        compression_ratio,
        data: base64_encode(&compressed),
    })
}

/// Decomprime un `CompressedPayload` e restituisce i byte JSON originali.
#[allow(dead_code)]
pub fn decompress_payload(payload: &CompressedPayload) -> Result<Vec<u8>> {
    let compressed = base64_decode(&payload.data)?;
    let decompressed = zstd::decode_all(compressed.as_slice())?;
    Ok(decompressed)
}

// ─── base64 senza dipendenze aggiuntive (semplice implementazione) ────────────

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        out.push(CHARS[b0 >> 2] as char);
        out.push(CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
        out.push(if chunk.len() > 1 { CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] as char } else { '=' });
        out.push(if chunk.len() > 2 { CHARS[b2 & 0x3f] as char } else { '=' });
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Result<u8> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => anyhow::bail!("carattere base64 non valido: {}", c),
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 { break; }
        let v = [val(chunk[0])?, val(chunk[1])?, val(chunk[2])?, val(chunk[3])?];
        out.push((v[0] << 2) | (v[1] >> 4));
        if chunk[2] != b'=' { out.push(((v[1] & 0xf) << 4) | (v[2] >> 2)); }
        if chunk[3] != b'=' { out.push(((v[2] & 3) << 6) | v[3]); }
    }
    Ok(out)
}
