# Crypto-from-scratch: implementation plan

A spec for building the core primitives in pure Python. Purpose is refreshing theory after five years away, not producing usable code.

## Ground rules

- **Pure Python standard library only.** No `cryptography`, no `pycryptodome`, no `gmpy2`. `secrets`, `os`, and `hashlib` are allowed freely — hashing is not part of what this exercise is trying to teach, so any stage that needs a hash may just call `hashlib.sha256`.
- **This is not production code and must be labeled as such.** No constant-time guarantees, no side-channel resistance, no memory hygiene. Put a header comment saying so in every file.
- **Every non-obvious step gets a comment explaining the algebra**, not the mechanics. Write "multiply by the fixed polynomial c(y) = 03y³ + 01y² + 01y + 02 in GF(2⁸)[y]/(y⁴+1)", not "multiply bytes and XOR".
- **Clarity over speed.** No bit-packing tricks, no precomputed tables except where the spec defines them (AES S-box). If there's a slow obvious way and a fast clever way, take the slow one.
- **Each module gets a `verify()` function** that runs official test vectors and asserts. No test framework needed.

## Build order

Each stage depends only on the ones before it. Build and verify one at a time.

### 1. `gf.py` — finite field arithmetic

Arithmetic in GF(2⁸) = F₂[x]/(x⁸+x⁴+x³+x+1), represented as integers 0–255.

- `gf_add(a, b)` — XOR
- `gf_mul(a, b)` — carryless multiply then reduce mod the AES polynomial
- `gf_inv(a)` — inverse via extended Euclid over F₂[x], or exponentiation by 254

Verify: `gf_mul(0x57, 0x83) == 0xc1` (the worked example in the Rijndael spec). Check that every nonzero element times its inverse is 1.

### 2. `aes.py` — the block cipher

128/192/256-bit keys, single-block encrypt and decrypt.

- S-box: build it programmatically from `gf_inv` composed with the affine transform over F₂, then assert it matches the published table. Do not hardcode the table as the primary definition — deriving it is the point.
- `key_expansion` — RotWord, SubWord, Rcon
- `sub_bytes`, `shift_rows`, `mix_columns`, `add_round_key` and their inverses
- `encrypt_block`, `decrypt_block`

Comments should establish that MixColumns is multiplication by a fixed element of GF(2⁸)[y]/(y⁴+1), and that y⁴+1 is not irreducible over GF(2⁸) but the chosen c(y) is still invertible there.

Verify: NIST FIPS-197 Appendix B and C vectors.

### 3. `gcm.py` — counter mode and GHASH

- CTR mode over `encrypt_block`
- GHASH: multiplication in GF(2¹²⁸) = F₂[x]/(x¹²⁸+x⁷+x²+x+1)
- `gcm_encrypt(key, nonce, plaintext, aad)` → `(ciphertext, tag)`
- `gcm_decrypt` with tag verification that raises on mismatch

**The bit-ordering convention is the main trap.** GCM treats the leftmost bit of a block as the *lowest-order* coefficient, which is the reverse of the usual convention and inverts the direction of the shift in the multiply loop. Have the implementation comment state this explicitly.

Also write a short demo, separate from the library, that encrypts two different plaintexts under the same key and nonce and recovers their XOR. Purpose is making the failure concrete.

Verify: NIST GCM test vectors, including cases with AAD and empty plaintext.

### 4. `mac.py` — HMAC and HKDF

- `hmac(key, msg)` over `hashlib.sha256`, with the ipad/opad construction and correct handling of over-length keys
- `hkdf_extract` and `hkdf_expand` per RFC 5869

Verify: RFC 4231 for HMAC, RFC 5869 appendix for HKDF.

### 5. `primes.py` — primality and prime generation

- Miller-Rabin with a configurable round count, `k=40` default
- Small-prime trial division sieve before the expensive test
- `generate_prime(bits)` using `secrets.randbits`, top bit and low bit forced

Comment should state the 3/4-per-round witness bound and where it comes from.

### 6. `rsa.py` — RSA

- `keygen(bits)` producing p, q, n, e=65537, d, and the CRT parameters dP, dQ, qInv
- Raw `encrypt`/`decrypt` and `sign`/`verify`
- CRT-accelerated private operation, with a comment on the isomorphism Z/nZ ≅ Z/pZ × Z/qZ
- OAEP and PSS, both built on MGF1 over `hashlib.sha256`

Add a `p` and `q` proximity check in keygen and a comment explaining Fermat factorization.

Verify: round-trip encrypt/decrypt and sign/verify at 2048 bits. RFC 8017 has OAEP and PSS vectors, but they require fixed randomness, so the functions need an optional seed parameter for testing.

### 7. `ec.py` — elliptic curve arithmetic

Short Weierstrass curves over prime fields. Target NIST P-256.

- Modular inverse via extended Euclid
- Point addition and doubling in affine coordinates, with the point at infinity handled explicitly
- Scalar multiplication by double-and-add
- Point compression and decompression (recovering y from x via the curve equation and a modular square root — P-256's prime is ≡ 3 mod 4, so the square root is a single exponentiation)

Verify: check that `n * G` is the point at infinity, and against published P-256 scalar multiplication vectors.

### 8. `ecdsa.py` — signatures

- `sign(d, msg)` and `verify(Q, msg, sig)`
- Implement the random-`k` version first
- Then implement RFC 6979 deterministic `k` using your HMAC from stage 4

Write a demo, separate from the library, that takes two signatures produced with the same `k` and recovers the private key algebraically. Same purpose as the GCM nonce demo — the two failures are structurally identical and seeing both makes the pattern stick.

## What to skip

Not worth the time for this exercise: AES modes other than CTR/GCM, RSA key serialization (ASN.1/DER is pure tedium), curves other than P-256, Ed25519 (different curve form, and the theory overlaps enough with ECDSA that it adds little), and any form of side-channel hardening.

## Suggested session split

- Session one: stages 1–3. The GF(2⁸) and GF(2¹²⁸) work is the densest algebra in the project.
- Session two: stages 4–6. Mostly mechanical; RSA is the familiar part.
- Session three: stages 7–8, plus the two failure demos.
