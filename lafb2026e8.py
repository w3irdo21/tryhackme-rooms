'''
Room Script: https://tryhackme.com/room/lafb2026e8

Medium Article for explanation: https://medium.com/@Sle3pyHead/signed-messages-ctf-notes-tryhackme-777aae147892

Installation Requirements
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install pycryptodome sympy
python lafb2026e8.py
'''

import hashlib
from sympy import nextprime
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# ---------------- CONFIG ----------------
TARGET_USER = "admin"

TARGET_MESSAGE = (
    "Welcome to LoveNote! Send encrypted love messages this Valentine's Day. "
    "Your communications are secured with industry-standard RSA-2048 digital signatures."
)

# ---------------- KEY GENERATION ----------------
def generate_admin_key():
    print("[*] Generating deterministic RSA key for admin")

    seed = f"{TARGET_USER}_lovenote_2026_valentine".encode()

    # Generate prime P
    p_hash = hashlib.sha256(seed).hexdigest()
    p = nextprime(int(p_hash, 16))

    # Generate prime Q
    q_hash = hashlib.sha256(seed + b"pki").hexdigest()
    q = nextprime(int(q_hash, 16))

    # RSA parameters
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    return RSA.construct((n, e, d))


# ---------------- SIGNATURE FORGERY ----------------
def forge_signature(key, message):
    h = SHA256.new(message.encode())

    # Calculate maximum allowed PSS salt
    modBits = key.size_in_bits()
    emLen = (modBits - 1 + 7) // 8
    maxSalt = emLen - h.digest_size - 2

    print(f"[*] Key size: {modBits} bits")
    print(f"[*] Max salt length: {maxSalt}")

    if maxSalt < 0:
        raise ValueError("Invalid key size")

    signer = pss.new(key, salt_bytes=maxSalt)
    signature = signer.sign(h)

    return signature.hex()


# ---------------- EXECUTION ----------------
if __name__ == "__main__":
    try:
        key = generate_admin_key()
        sig = forge_signature(key, TARGET_MESSAGE)

        print("\n" + "=" * 60)
        print("ADMIN SIGNATURE:")
        print(sig)
        print("=" * 60)

    except Exception as err:
        print(f"[!] Error: {err}")
