"""Pure-Python ECDSA (secp256k1 and NIST P-256) with RFC 6979 deterministic
nonces. Standard library only; no third-party packages, no network, no
hardware. Used by the attestation models as a SIMULATED stand-in for the
real signature primitives (TPM AK = ECC P-256; validator manifest keys =
secp256k1, as used by the pinned postfiatd source). Test keys are fixed
constants, clearly labelled, and never used outside the models.
"""

import hashlib
import hmac


class Curve:
    def __init__(self, name, p, a, b, gx, gy, n):
        self.name = name
        self.p = p
        self.a = a
        self.b = b
        self.g = (gx, gy)
        self.n = n

    def add(self, p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None
        if p1 == p2:
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p) % self.p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mul(self, k, point):
        result = None
        addend = point
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return result

    def pubkey(self, priv):
        return self.mul(priv % self.n, self.g)


SECP256K1 = Curve(
    "secp256k1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)

P256 = Curve(
    "nist-p256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)


def _rfc6979_k(curve, priv, msg_hash):
    """Deterministic nonce per RFC 6979 using HMAC-SHA256."""
    qlen = (curve.n.bit_length() + 7) // 8
    bx = priv.to_bytes(qlen, "big") + msg_hash
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + bx, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + bx, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < curve.n:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(curve, priv, msg_hash):
    """Return (r, s) with low-s normalisation. msg_hash is a 32-byte digest."""
    z = int.from_bytes(msg_hash, "big")
    k = _rfc6979_k(curve, priv, msg_hash)
    r = curve.mul(k, curve.g)[0] % curve.n
    s = (pow(k, -1, curve.n) * (z + r * priv)) % curve.n
    if s > curve.n // 2:
        s = curve.n - s
    return (r, s)


def verify(curve, pub, msg_hash, r, s):
    """Return True iff (r, s) is a valid signature of msg_hash under pub."""
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False
    z = int.from_bytes(msg_hash, "big")
    w = pow(s, -1, curve.n)
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n
    point = curve.add(curve.mul(u1, curve.g), curve.mul(u2, pub))
    if point is None:
        return False
    return point[0] % curve.n == r


def point_hex(point):
    x, y = point
    return "04" + "%064x" % x + "%064x" % y


def sig_hex(r, s):
    return "%064x%064x" % (r, s)
