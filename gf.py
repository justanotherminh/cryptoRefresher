"""
gf.py — arithmetic in the finite field GF(2^8).

NOT PRODUCTION CODE. Written to relearn the theory. No constant-time
guarantees, no side-channel resistance, no memory hygiene. Do not use this
to protect anything.

The field
---------
GF(2^8) is built as the quotient ring F_2[x] / (m(x)), where

    m(x) = x^8 + x^4 + x^3 + x + 1        (0x11B, the AES polynomial)

m(x) is irreducible over F_2, so the ideal (m(x)) is maximal and the quotient
is a field with 2^8 = 256 elements.

Every residue class has a unique representative of degree < 8,
b7·x^7 + ... + b1·x + b0 with each bi in F_2. We store it as the integer whose
bit i is bi, so 0x57 = 0b01010111 stands for x^6 + x^4 + x^2 + x + 1.
The same integer encoding is used for unreduced polynomials in F_2[x].
"""

AES_MODULUS = 0x11B  # m(x) = x^8 + x^4 + x^3 + x + 1


def _degree(p):
    """Degree of p in F_2[x]. The zero polynomial gets degree -1."""
    return p.bit_length() - 1


# ---------------------------------------------------------------------------
# The polynomial ring F_2[x]
# ---------------------------------------------------------------------------

def poly_mul(a, b):
    """Product a(x)·b(x) in F_2[x], not reduced."""
    # a(x)·b(x) = sum of a(x)·x^i over every i where b has a nonzero coefficient.
    # Multiplying by x^i moves each coefficient up i places. Coefficients add
    # in F_2, where 1 + 1 = 0, so nothing carries into the next degree. That is
    # why this is called "carryless" multiplication.
    result = 0
    i = 0
    while (b >> i) != 0:
        if (b >> i) & 1:
            result ^= a << i
        i += 1
    return result


def poly_divmod(a, b):
    """Long division in F_2[x]: returns (q, r) with a = q·b + r and deg r < deg b."""
    if b == 0:
        raise ZeroDivisionError("division by the zero polynomial")
    q = 0
    while _degree(a) >= _degree(b):
        # Over F_2 every nonzero leading coefficient is 1, so the next quotient
        # term is just x^(deg a - deg b). Subtracting that multiple of b clears
        # a's leading term. In characteristic 2, subtracting is the same as adding.
        shift = _degree(a) - _degree(b)
        q ^= 1 << shift
        a ^= b << shift
    return q, a


# ---------------------------------------------------------------------------
# The field GF(2^8) = F_2[x] / (m(x))
# ---------------------------------------------------------------------------

def gf_add(a, b):
    # Adding polynomials adds matching coefficients in F_2, and that is XOR.
    # The field has characteristic 2, so a + a = 0: every element is its own
    # negative and subtraction is the same operation.
    return a ^ b


def gf_mul(a, b):
    # Multiply the representatives in F_2[x], then pick the canonical
    # representative of the product's class: its remainder mod m(x).
    # This is well defined because (m(x)) is an ideal. Adding a multiple of
    # m(x) to either input adds a multiple of m(x) to the product.
    _, r = poly_divmod(poly_mul(a, b), AES_MODULUS)
    return r


def gf_pow(a, e):
    """a^e in GF(2^8) by square-and-multiply."""
    # Write e in binary as e = sum of 2^i over its set bits. Then
    # a^e = product of a^(2^i) over those bits, and each a^(2^i) is the square
    # of the one before it.
    result = 1
    square = a
    while e > 0:
        if e & 1:
            result = gf_mul(result, square)
        square = gf_mul(square, square)
        e >>= 1
    return result


def gf_inv(a):
    """Multiplicative inverse in GF(2^8), by extended Euclid over F_2[x].

    0 has no inverse. We return 0 for it anyway, because that is the value
    the AES S-box definition uses at 0.
    """
    if a == 0:
        return 0
    # m(x) is irreducible and a(x) is a nonzero polynomial of degree < 8,
    # so gcd(a, m) = 1. Bezout's identity then gives s(x), t(x) with
    #     s(x)·a(x) + t(x)·m(x) = 1.
    # Reducing mod m(x) removes the second term, leaving s(x)·a(x) ≡ 1.
    # So s is the inverse, and we never need to compute t.
    #
    # Loop invariant: s_i · a ≡ r_i (mod m) for both tracked pairs.
    # It starts true: r = m ≡ 0 = 0·a, and r = a = 1·a.
    r_prev, r_curr = AES_MODULUS, a
    s_prev, s_curr = 0, 1
    while r_curr != 0:
        q, rem = poly_divmod(r_prev, r_curr)
        r_prev, r_curr = r_curr, rem
        # r_{i+1} = r_{i-1} - q·r_i, so the same combination keeps the invariant:
        # s_{i+1} = s_{i-1} - q·s_i. Minus is XOR in F_2[x].
        s_prev, s_curr = s_curr, s_prev ^ poly_mul(q, s_curr)
    # The last nonzero remainder is the gcd. The only nonzero constant in F_2[x] is 1.
    assert r_prev == 1, "gcd(a, m) != 1: the modulus is not irreducible"
    _, inv = poly_divmod(s_prev, AES_MODULUS)
    return inv


def gf_inv_fermat(a):
    """Inverse via a^254. Kept as an independent cross-check on gf_inv."""
    # The nonzero elements form a multiplicative group of order 2^8 - 1 = 255.
    # By Lagrange's theorem every nonzero a satisfies a^255 = 1,
    # so a^254 = a^(-1). At a = 0 this also gives 0^254 = 0.
    return gf_pow(a, 254)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify():
    # m(x) has degree 8. If it were reducible it would have a factor of degree
    # 1 to 4. Check every polynomial in that range (0x02 through 0x1F) and
    # confirm none divides m.
    for d in range(0x02, 0x20):
        _, r = poly_divmod(AES_MODULUS, d)
        assert r != 0, f"m(x) is divisible by {d:#x}"

    # FIPS-197 section 4.1: {57} + {83} = {d4}
    assert gf_add(0x57, 0x83) == 0xD4
    # FIPS-197 section 4.2: {57} • {83} = {c1}, the worked example
    assert gf_mul(0x57, 0x83) == 0xC1
    # FIPS-197 section 4.2.1: {57} • {13} = {fe}, the xtime example
    assert gf_mul(0x57, 0x13) == 0xFE
    # Commonly quoted inverse pair from the S-box derivation: {53}^-1 = {ca}
    assert gf_inv(0x53) == 0xCA

    # Every nonzero element times its inverse is 1, and the two inversion
    # methods agree on every element.
    for a in range(1, 256):
        inv = gf_inv(a)
        assert gf_mul(a, inv) == 1, f"{a:#04x} * {inv:#04x} != 1"
        assert inv == gf_inv_fermat(a), f"Euclid and Fermat disagree at {a:#04x}"
    assert gf_inv(0) == 0 == gf_inv_fermat(0)

    # Multiplication must be commutative and must distribute over addition.
    # Checking every triple would take 16M cases, so check a fixed sample.
    sample = [0x00, 0x01, 0x02, 0x03, 0x53, 0x57, 0x83, 0xCA, 0xFF]
    for a in sample:
        for b in sample:
            assert gf_mul(a, b) == gf_mul(b, a)
            for c in sample:
                assert gf_mul(a, gf_add(b, c)) == gf_add(gf_mul(a, b), gf_mul(a, c))


if __name__ == "__main__":
    verify()
    print("gf.py: all checks passed")
