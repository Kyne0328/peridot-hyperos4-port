#!/usr/bin/env python3
"""RI3 Android whole-file ZIP verifier. Independent of signer/OpenSSL.
Uses bounded file reads, a strict DER parser, Python modular exponentiation,
and cryptography only to decode the caller's trusted public X.509 certificate.
"""
import argparse, base64, hashlib, json, pathlib, struct
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

TRUSTED_CERT_SHA256 = "24adea378cba169a0852bce0ffd5ee1874940f16b73c873efc75d57129f080cf"
SHA256_OID = bytes.fromhex("608648016503040201")
RSA_OID = bytes.fromhex("2a864886f70d010101")
SHA256_RSA_OID = "1.2.840.113549.1.1.11"
SIGNED_DATA_OID = bytes.fromhex("2a864886f70d010702")
DATA_OID = bytes.fromhex("2a864886f70d010701")
EOCD = b"PK\x05\x06"
CHUNK = 1024 * 1024

class VerificationError(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise VerificationError(reason)

class DER:
    def __init__(self, data):
        self.data, self.pos = data, 0
    def item(self, tag=None):
        start = self.pos
        need(start + 2 <= len(self.data), "DER truncated header")
        actual, n = self.data[start:start+2]
        p = start + 2
        if n & 128:
            count = n & 127
            need(0 < count <= 4 and p+count <= len(self.data), "DER indefinite/oversized length")
            need(self.data[p] != 0, "DER nonminimal length")
            n = int.from_bytes(self.data[p:p+count], "big")
            need(n >= 128, "DER nonminimal long length")
            p += count
        need(p+n <= len(self.data), "DER truncated value")
        if tag is not None:
            need(actual == tag, "DER unexpected tag")
        self.pos = p+n
        return actual, self.data[p:p+n], self.data[start:p+n]
    def body(self, tag):
        return DER(self.item(tag)[1])
    def end(self):
        need(self.pos == len(self.data), "DER extra elements")
    def peek(self):
        return self.data[self.pos] if self.pos < len(self.data) else None

def algorithm(d, oid):
    a = d.body(0x30)
    need(a.item(6)[1] == oid, "Unexpected algorithm OID")
    if a.peek() is not None:
        need(a.item(5)[1] == b"", "Algorithm parameters must be NULL")
    a.end()

def certificate(path, expected=TRUSTED_CERT_SHA256):
    pem = pathlib.Path(path).read_bytes()
    need(len(pem) <= 65536, "Certificate exceeds 64 KiB")
    cert = x509.load_pem_x509_certificate(pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    fp = hashlib.sha256(der).hexdigest()
    need(fp == expected, "Trusted certificate fingerprint mismatch")
    need(cert.signature_algorithm_oid.dotted_string == SHA256_RSA_OID,
         "Recovery must select SHA256 from trusted certificate algorithm")
    pub = cert.public_key()
    need(isinstance(pub, rsa.RSAPublicKey), "Trusted certificate is not RSA")
    numbers = pub.public_numbers()
    need(pub.key_size in (2048,4096) and numbers.e in (3,65537),
         "Recovery-incompatible RSA parameters")
    return cert, der, fp, numbers.n, numbers.e

def extract_signature(cms, trusted_der):
    top = DER(cms); info = top.body(0x30); top.end()
    need(info.item(6)[1] == SIGNED_DATA_OID, "CMS content is not SignedData")
    wrap = info.body(0xa0); info.end()
    sd = wrap.body(0x30); wrap.end()
    need(sd.item(2)[1] == b"\x01", "CMS version must be 1")
    hashes = sd.body(0x31); algorithm(hashes, SHA256_OID); hashes.end()
    enc = sd.body(0x30)
    need(enc.item(6)[1] == DATA_OID, "CMS content type must be data")
    enc.end()  # Detached only, no encapContent.
    certs = sd.body(0xa0)
    embedded = certs.item(0x30)[2]; certs.end()
    need(embedded == trusted_der, "CMS certificate differs from trusted certificate")
    signers = sd.body(0x31); sd.end()
    si = signers.body(0x30); signers.end()
    need(si.item(2)[1] == b"\x01", "SignerInfo version must be 1")
    tc = DER(trusted_der).body(0x30).body(0x30)
    if tc.peek() == 0xa0: tc.item(0xa0)
    expected_serial = tc.item(2)[2]
    tc.item(0x30)
    expected_issuer = tc.item(0x30)[2]
    sid = si.body(0x30)
    need(sid.item(0x30)[2] == expected_issuer and sid.item(2)[2] == expected_serial,
         "CMS issuer/serial differs from trusted certificate")
    sid.end()
    algorithm(si, SHA256_OID)
    need(si.peek() == 0x30, "Signed attributes are not recovery-compatible")
    algorithm(si, RSA_OID)
    signature = si.item(4)[1]
    si.end()
    return signature

def verify_rsa(signature, digest, modulus, exponent):
    width = (modulus.bit_length()+7)//8
    need(len(signature) == width, "RSA signature width mismatch")
    value = int.from_bytes(signature, "big")
    need(value < modulus, "RSA signature out of range")
    encoded = pow(value, exponent, modulus).to_bytes(width, "big")
    suffix = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    expected = b"\0\1" + b"\xff"*(width-len(suffix)-3) + b"\0" + suffix
    need(encoded == expected, "RSA-SHA256 signature mismatch")

def envelope(path):
    path = pathlib.Path(path)
    size = path.stat().st_size
    need(size >= 28, "Too small for signed ZIP")
    with path.open("rb") as f:
        f.seek(-6,2); footer = f.read(6)
        start, marker, comment = struct.unpack("<HHH",footer)
        need(marker == 65535, "Android footer marker mismatch")
        need(6 < start <= comment, "Signature start outside ZIP comment")
        need(size >= comment+22, "EOCD outside file")
        f.seek(size-comment-22); eocd = f.read(comment+22)
    need(eocd[:4] == EOCD, "EOCD marker mismatch")
    need(struct.unpack_from("<H",eocd,20)[0] == comment, "EOCD/footer comment length mismatch")
    need(EOCD not in eocd[4:], "Additional EOCD marker after EOCD start")
    cms = eocd[len(eocd)-start:-6]
    return {"size":size, "signed_bytes":size-comment-2,
            "comment_bytes":comment, "signature_start":start,
            "cms_bytes":len(cms)}, cms

def verify_zip(path, cert_path, expected_cert_sha256=TRUSTED_CERT_SHA256):
    cert, der, fingerprint, n, e = certificate(cert_path, expected_cert_sha256)
    result, cms = envelope(path)
    signature = extract_signature(cms, der)
    whole, signed = hashlib.sha256(), hashlib.sha256()
    with pathlib.Path(path).open("rb") as f:
        remaining = result["signed_bytes"]
        while remaining:
            block = f.read(min(CHUNK,remaining))
            need(bool(block), "Truncated signed range")
            signed.update(block); whole.update(block); remaining -= len(block)
        while block := f.read(CHUNK):
            whole.update(block)
    verify_rsa(signature, signed.digest(), n, e)
    result.update({"verified":True, "sha256":whole.hexdigest(),
        "signed_sha256":signed.hexdigest(), "certificate_der_sha256":fingerprint,
        "algorithm":"RSA-PKCS1-v1_5-SHA256-direct",
        "implementation":"independent Python DER + modular RSA; public X509 decode via cryptography",
        "io_chunk_bytes":CHUNK})
    return result

if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("zip"); p.add_argument("--cert",required=True)
    p.add_argument("--expected-cert-sha256",default=TRUSTED_CERT_SHA256)
    p.add_argument("--report")
    a=p.parse_args()
    try:
        r=verify_zip(a.zip,a.cert,a.expected_cert_sha256)
    except Exception as ex:
        r={"verified":False,"error":str(ex)}
    text=json.dumps(r,indent=2)+"\n"
    if a.report: pathlib.Path(a.report).write_text(text)
    print(text)
    raise SystemExit(0 if r["verified"] else 1)
