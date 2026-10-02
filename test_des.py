"""
test_des.py
Tests the manual DES implementation.
"""

from des import crypt_block, generate_round_keys, encrypt_to_hex, decrypt_from_hex

# NIST/FIPS-style DES known-answer test.
# Key       = 133457799BBCDFF1
# Plaintext = 0123456789ABCDEF
# Expected  = 85E813540F0AB405

key = bytes.fromhex("133457799BBCDFF1")
plaintext = bytes.fromhex("0123456789ABCDEF")
expected = "85E813540F0AB405"

actual = crypt_block(plaintext, generate_round_keys(key)).hex().upper()

print("=" * 60)
print("MANUAL DES TEST")
print("=" * 60)
print("Expected:", expected)
print("Actual  :", actual)

assert actual == expected, "DES known-answer test FAILED."
print("[PASS] Standard DES block test.")

messages = [
    "Hello World",
    "Halo, ini pesan rahasia!",
    "Komunikasi dua arah DES.",
    "Pesan dengan UTF-8: Indonesia",
]

shared_key = "MYKEY123"

for message in messages:
    ciphertext = encrypt_to_hex(message, shared_key)
    recovered = decrypt_from_hex(ciphertext, shared_key)

    assert recovered == message

    print("\nPlaintext :", message)
    print("Ciphertext:", ciphertext)
    print("Decrypted :", recovered)

print("\n[PASS] All encryption/decryption tests passed.")
