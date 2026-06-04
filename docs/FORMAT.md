# Kasa vault format (v1)

This document specifies the exact on-disk layout of a Kasa vault so that the
contents can be recovered **even without this exact program** — any tool with a
libsodium binding (or `libsodium` itself) can re-implement the reader from this
spec. Keep this file with the repository; it is your long-term insurance.

All multi-byte integers are **big-endian**. All cryptography is libsodium.

## 1. File layout

```
+----------------------------------------------------------+
| MAGIC                8 bytes   ASCII "KASAVLT1"           |
| header_length        uint32    length of the JSON header  |
| header               N bytes   UTF-8 JSON (see §2)        |
+----------------------------------------------------------+
| repeated, until the FINAL chunk:                         |
|   chunk_length       uint32    length of the ciphertext   |
|   ciphertext_chunk   M bytes   one secretstream message   |
+----------------------------------------------------------+
```

The byte string `MAGIC` is `b"KASAVLT1"`. If the first 8 bytes differ, the file
is not a Kasa vault.

## 2. Header (JSON, non-secret)

The header contains **no secrets** — only the public parameters needed to derive
the key and start the stream. Example (whitespace added for readability):

```json
{
  "magic": "KASA",
  "version": 1,
  "cipher": "xchacha20poly1305-secretstream",
  "kdf": "argon2id",
  "kdf_salt": "<base64, 16 bytes>",
  "kdf_ops": 4,
  "kdf_mem": 1073741824,
  "dek_nonce": "<base64, 24 bytes>",
  "dek_wrapped": "<base64, 48 bytes>",
  "stream_header": "<base64, 24 bytes>",
  "chunk": 1048576,
  "compress": "none",
  "created": "2026-06-02T19:00:00Z"
}
```

Field meanings:

| field           | meaning                                                                 |
|-----------------|-------------------------------------------------------------------------|
| `version`       | format version (currently `1`).                                         |
| `cipher`        | always `xchacha20poly1305-secretstream`.                                |
| `kdf`           | always `argon2id`.                                                       |
| `kdf_salt`      | base64 of the 16-byte Argon2id salt.                                    |
| `kdf_ops`       | Argon2id `opslimit` (an integer).                                       |
| `kdf_mem`       | Argon2id `memlimit` in **bytes**.                                       |
| `dek_nonce`     | base64 of the 24-byte XChaCha20-Poly1305-IETF nonce for the envelope.   |
| `dek_wrapped`   | base64 of the AEAD-encrypted Data Encryption Key (32-byte key + 16-byte tag = 48 bytes). |
| `stream_header` | base64 of the 24-byte secretstream header.                              |
| `chunk`         | plaintext chunk size used when writing (1 MiB). Informational.          |
| `compress`      | `"gz"` if the inner tar is gzip-compressed, otherwise `"none"`.         |
| `created`       | ISO-8601 UTC timestamp. Informational.                                  |

> Note: the inner JSON also carries `"magic": "KASA"`. This is a redundant,
> human-readable marker and is **not** the file signature; the file signature is
> the 8-byte binary `MAGIC` at offset 0.

## 3. Key schedule (envelope encryption)

There are two keys:

* **KEK** (key-encrypting key) — derived from the password.
* **DEK** (data-encrypting key) — a random 32-byte key that actually encrypts the
  payload. It is stored only in *wrapped* (encrypted) form in the header.

### 3.1 Derive the KEK

```
KEK = argon2id(
    out_len = 32,
    password = <UTF-8 bytes of the master password>,
    salt     = base64_decode(kdf_salt),     # 16 bytes
    opslimit = kdf_ops,
    memlimit = kdf_mem,                      # bytes
)
```
(libsodium: `crypto_pwhash` with `crypto_pwhash_ALG_ARGON2ID13`.)

### 3.2 Unwrap the DEK

The DEK is wrapped with XChaCha20-Poly1305-IETF (`crypto_aead_xchacha20poly1305_ietf`).
The **associated data (AAD)** binds the format and KDF parameters, so tampering
with the header (e.g. lowering the cost) makes decryption fail:

```
AAD = MAGIC                       # b"KASAVLT1", 8 bytes
    || uint32_be(version)         # 4 bytes, value 1
    || uint64_be(kdf_ops)         # 8 bytes
    || uint64_be(kdf_mem)         # 8 bytes
    || salt                       # 16 bytes
```

Then:

```
DEK = aead_xchacha20poly1305_ietf_decrypt(
    ciphertext = base64_decode(dek_wrapped),
    aad        = AAD,
    nonce      = base64_decode(dek_nonce),
    key        = KEK,
)
```
If this fails, the password is wrong or the header was tampered with.

## 4. Payload (secretstream)

The payload after the header is an XChaCha20-Poly1305 **secretstream**
(`crypto_secretstream_xchacha20poly1305`).

```
state = secretstream_init_pull(
    header = base64_decode(stream_header),   # 24 bytes
    key    = DEK,
)
```

Then read chunks in a loop:

```
loop:
    read 4 bytes -> chunk_length (uint32_be)   # EOF here without a FINAL tag = truncated/corrupt
    read chunk_length bytes -> ciphertext_chunk
    (plaintext, tag) = secretstream_pull(state, ciphertext_chunk, ad)
    append plaintext to the payload stream
    if tag == TAG_FINAL (3): stop
```

**Associated data per chunk (`ad`):**

* For the **first** chunk only: `ad = b"KASAVLT1/stream"` (the constant `STREAM_AD`).
* For every subsequent chunk: `ad = b""` (empty).

A correct stream ends with exactly one chunk carrying the `TAG_FINAL` (value 3)
tag. If the stream ends before a FINAL tag is seen, the file was truncated and
must be rejected.

## 5. Inner archive

The concatenated plaintext from §4 is a POSIX **tar** stream in PAX format. If
`compress == "gz"`, it is gzip-compressed (decompress first). Extract it to get
the original files and directories.

> Security note for re-implementers: validate each tar member before extraction
> (reject absolute paths, `..` traversal, device/special files, and symlinks
> that escape the destination). The reference implementation does this in
> `core._safe_member`.

## 6. Changing the password

Because the payload is encrypted under the DEK (not the password), changing the
password only re-derives a new KEK (with a fresh salt) and re-wraps the same DEK.
The ciphertext stream is copied byte-for-byte. This is why `kasa passwd` is
instantaneous regardless of vault size, and why the first chunk's associated
data is a fixed constant rather than the header (so the stream stays valid when
the header changes).

## 7. Minimal recovery checklist

1. Install this repo's tool and run: `kasa open -v /path/to/my-vault.enc`
   (or `nix run github:<you>/kasa -- open -v /path/to/my-vault.enc`).
2. If the tool is unavailable, any libsodium binding can decrypt by following
   §3–§5 above. The only secret required is your master password.
