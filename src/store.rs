//! The encrypted secret store.
//!
//! One file, one passphrase, no daemon required:
//!
//! ```text
//! confmask store init
//! confmask store set DEPLOY_TOKEN < token.txt
//! confmask run --secret DEPLOY_TOKEN=daemon:DEPLOY_TOKEN -- ./deploy.sh
//! ```
//!
//! At rest the file is XChaCha20-Poly1305 ciphertext under an Argon2id
//! key; the header (KDF parameters, salt, nonce) is authenticated as
//! associated data, so it cannot be weakened without the tag failing.
//!
//! Why a store at all: the alternative on a shared host is a plaintext
//! `.env`, a `~/.config` file, or a token pasted into a runner's
//! configuration.  All of those are readable by anything running as the
//! same account — including the job that is supposed to be untrusted.

use crate::mem::SecBuf;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const MAGIC: &[u8; 16] = b"CONFMASKSTORE1\0\0";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Argon2id cost.  The OWASP 2024 baseline for interactive use; it is
/// what a phone and a CI runner can both afford.
#[derive(Debug, Clone, Copy)]
pub struct Params2 {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Params2 {
    fn default() -> Self {
        Params2 {
            m_cost: 19 * 1024, // KiB == 19 MiB
            t_cost: 2,
            p_cost: 1,
        }
    }
}

/// A passphrase, held in protected memory.
pub struct Passphrase(SecBuf);

impl Passphrase {
    pub fn new(bytes: &[u8]) -> io::Result<Passphrase> {
        Ok(Passphrase(SecBuf::from_slice(bytes)?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Read a passphrase from a file (first line, newline trimmed).
    pub fn from_file(p: &Path) -> io::Result<Passphrase> {
        let mut f = std::fs::File::open(p)?;
        let md = f.metadata()?;
        if md.permissions().mode() & 0o077 != 0 {
            eprintln!(
                "confmask: warning: passphrase file {} is group/world readable",
                p.display()
            );
        }
        let mut v = Vec::new();
        f.read_to_end(&mut v)?;
        if v.last() == Some(&b'\n') {
            v.pop();
        }
        let pp = Passphrase::new(&v)?;
        v.zeroize();
        Ok(pp)
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        // SAFETY: writing into our own buffer.
        let n = unsafe {
            libc::getrandom(
                buf[off..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - off,
                0,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        off += n as usize;
    }
    Ok(())
}

fn derive_key(
    passphrase: &Passphrase,
    salt: &[u8],
    params: Params2,
) -> io::Result<[u8; KEY_LEN]> {
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut key = [0u8; KEY_LEN];
    a.hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok(key)
}

/// An unlocked store.
pub struct Store {
    path: PathBuf,
    entries: BTreeMap<String, SecBuf>,
    params: Params2,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.path)
            .field("entries", &self.entries.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn encode_plaintext(entries: &BTreeMap<String, SecBuf>) -> io::Result<SecBuf> {
    let mut total = 4usize;
    for (k, v) in entries {
        total += 2 + k.len() + 4 + v.len();
    }
    let mut out = SecBuf::new(total)?;
    let mut o = 0usize;
    let put = |out: &mut SecBuf, bytes: &[u8], o: &mut usize| {
        out.as_mut_slice()[*o..*o + bytes.len()].copy_from_slice(bytes);
        *o += bytes.len();
    };
    put(&mut out, &(entries.len() as u32).to_le_bytes(), &mut o);
    for (k, v) in entries {
        put(&mut out, &(k.len() as u16).to_le_bytes(), &mut o);
        put(&mut out, k.as_bytes(), &mut o);
        put(&mut out, &(v.len() as u32).to_le_bytes(), &mut o);
        put(&mut out, v.as_slice(), &mut o);
    }
    Ok(out)
}

fn decode_plaintext(buf: &SecBuf) -> io::Result<BTreeMap<String, SecBuf>> {
    let b = buf.as_slice();
    let mut o = 0usize;
    let take = |o: &mut usize, n: usize| -> io::Result<&[u8]> {
        if *o + n > b.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "store plaintext truncated",
            ));
        }
        let s = &b[*o..*o + n];
        *o += n;
        Ok(s)
    };
    let count = u32::from_le_bytes(take(&mut o, 4)?.try_into().unwrap()) as usize;
    let mut m = BTreeMap::new();
    for _ in 0..count {
        let kl = u16::from_le_bytes(take(&mut o, 2)?.try_into().unwrap()) as usize;
        let name = String::from_utf8(take(&mut o, kl)?.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "store: bad name"))?;
        let vl = u32::from_le_bytes(take(&mut o, 4)?.try_into().unwrap()) as usize;
        let val = take(&mut o, vl)?;
        m.insert(name, SecBuf::from_slice(val)?);
    }
    Ok(m)
}

impl Store {
    /// Create a new, empty store and write it out.
    pub fn create(path: &Path, passphrase: &Passphrase) -> io::Result<Store> {
        let s = Store {
            path: path.to_path_buf(),
            entries: BTreeMap::new(),
            params: Params2::default(),
        };
        s.save(passphrase)?;
        Ok(s)
    }

    /// Unlock an existing store.
    pub fn open(path: &Path, passphrase: &Passphrase) -> io::Result<Store> {
        let mut f = std::fs::File::open(path)?;
        let md = f.metadata()?;
        if md.permissions().mode() & 0o077 != 0 {
            eprintln!(
                "confmask: warning: store {} is group/world readable",
                path.display()
            );
        }
        let mut blob = Vec::new();
        f.read_to_end(&mut blob)?;

        if blob.len() < 16 + 12 + 1 + 1 + 8 || &blob[..16] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a confmask store (bad magic)",
            ));
        }
        let mut o = 16usize;
        let m_cost = u32::from_le_bytes(blob[o..o + 4].try_into().unwrap());
        o += 4;
        let t_cost = u32::from_le_bytes(blob[o..o + 4].try_into().unwrap());
        o += 4;
        let p_cost = u32::from_le_bytes(blob[o..o + 4].try_into().unwrap());
        o += 4;
        let sl = blob[o] as usize;
        o += 1;
        if sl != SALT_LEN || o + sl > blob.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad salt"));
        }
        let salt = blob[o..o + sl].to_vec();
        o += sl;
        let nl = blob[o] as usize;
        o += 1;
        if nl != NONCE_LEN || o + nl > blob.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad nonce"));
        }
        let nonce = blob[o..o + nl].to_vec();
        o += nl;
        let cl = u64::from_le_bytes(blob[o..o + 8].try_into().unwrap()) as usize;
        o += 8;
        if o + cl != blob.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad length"));
        }
        let ct = &blob[o..];

        let params = Params2 {
            m_cost,
            t_cost,
            p_cost,
        };
        let mut key = derive_key(passphrase, &salt, params)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        key.zeroize();

        let aad = &blob[..16 + 12 + 1 + sl + 1 + nl];
        let plain = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload { msg: ct, aad },
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cannot decrypt store: wrong passphrase or corrupted file",
                )
            })?;

        let mut sb = SecBuf::new(plain.len())?;
        sb.as_mut_slice().copy_from_slice(&plain);
        let mut plain = plain;
        plain.zeroize();
        let entries = decode_plaintext(&sb)?;
        blob.zeroize();
        Ok(Store {
            path: path.to_path_buf(),
            entries,
            params,
        })
    }

    /// Re-encrypt and write the store atomically.
    pub fn save(&self, passphrase: &Passphrase) -> io::Result<()> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        random_bytes(&mut salt)?;
        random_bytes(&mut nonce)?;

        let plain = encode_plaintext(&self.entries)?;
        let mut key = derive_key(passphrase, &salt, self.params)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        key.zeroize();

        let mut header = Vec::with_capacity(16 + 12 + 1 + SALT_LEN + 1 + NONCE_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&self.params.m_cost.to_le_bytes());
        header.extend_from_slice(&self.params.t_cost.to_le_bytes());
        header.extend_from_slice(&self.params.p_cost.to_le_bytes());
        header.push(SALT_LEN as u8);
        header.extend_from_slice(&salt);
        header.push(NONCE_LEN as u8);
        header.extend_from_slice(&nonce);

        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plain.as_slice(),
                    aad: &header,
                },
            )
            .map_err(|_| io::Error::other("encryption failed"))?;

        let tmp = self.path.with_extension("tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&header)?;
            f.write_all(&(ct.len() as u64).to_le_bytes())?;
            f.write_all(&ct)?;
            f.sync_all()?;
        }
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn set(&mut self, name: &str, value: &[u8]) -> io::Result<()> {
        self.entries
            .insert(name.to_string(), SecBuf::from_slice(value)?);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.entries.get(name).map(|b| b.as_slice())
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.entries.remove(name).is_some()
    }

    pub fn names(&self) -> Vec<&str> {
        self.entries.keys().map(|s| s.as_str()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Where the store lives when no `--store` is given.
pub fn default_path() -> PathBuf {
    if let Some(p) = std::env::var_os("CONFMASK_STORE") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("confmask").join("store.enc")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("confmask-store-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn roundtrip() {
        let d = tmpdir();
        let p = d.join("s.enc");
        let pp = Passphrase::new(b"correct horse").unwrap();
        let mut s = Store::create(&p, &pp).unwrap();
        s.set("A", b"one").unwrap();
        s.set("B", b"two").unwrap();
        s.save(&pp).unwrap();

        let s2 = Store::open(&p, &pp).unwrap();
        assert_eq!(s2.get("A"), Some(&b"one"[..]));
        assert_eq!(s2.get("B"), Some(&b"two"[..]));
        assert_eq!(s2.names(), vec!["A", "B"]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn wrong_passphrase_fails() {
        let d = tmpdir();
        let p = d.join("w.enc");
        let pp = Passphrase::new(b"right").unwrap();
        let mut s = Store::create(&p, &pp).unwrap();
        s.set("A", b"one").unwrap();
        s.save(&pp).unwrap();
        let bad = Passphrase::new(b"wrong").unwrap();
        assert!(Store::open(&p, &bad).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn file_is_0600() {
        let d = tmpdir();
        let p = d.join("m.enc");
        let pp = Passphrase::new(b"x").unwrap();
        Store::create(&p, &pp).unwrap();
        let md = std::fs::metadata(&p).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let d = tmpdir();
        let p = d.join("c.enc");
        let pp = Passphrase::new(b"x").unwrap();
        let mut s = Store::create(&p, &pp).unwrap();
        s.set("TOKEN", b"SUPERSECRETVALUE").unwrap();
        s.save(&pp).unwrap();
        let raw = std::fs::read(&p).unwrap();
        assert!(!raw.windows(16).any(|w| w == b"SUPERSECRETVALUE"));
        std::fs::remove_file(&p).ok();
    }
}
