import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def generate_aes_key_iv():
    key = os.urandom(32)  # AES-256
    iv = os.urandom(12)   # Use 12 bytes for AES-GCM IV
    return key, iv


def encrypt_data(plaintext, key, iv):
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return ciphertext, encryptor.tag


def decrypt_data(ciphertext, key, iv, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_key_with_rsa(aes_key, public_key_base64):
    public_key_pem = (
        "-----BEGIN PUBLIC KEY-----\n" +
        "\n".join([public_key_base64[i:i + 64] for i in range(0, len(public_key_base64), 64)]) +
        "\n-----END PUBLIC KEY-----\n"
    )

    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def encryption_mode(public_key_base64):
    plaintext = input("Enter plaintext to encrypt: ")
    aes_key, iv = generate_aes_key_iv()
    ciphertext, tag = encrypt_data(plaintext, aes_key, iv)
    encrypted_key = encrypt_key_with_rsa(aes_key, public_key_base64)

    print("\n--- Encryption Output ---")
    print(f"AES Key (Base64): {base64.b64encode(aes_key).decode()}")
    print(f"IV (Base64): {base64.b64encode(iv).decode()}")
    print(f"Auth Tag (Base64): {base64.b64encode(tag).decode()}")
    print(f"Ciphertext (Base64): {base64.b64encode(ciphertext).decode()}")
    print(f"Encrypted AES Key (Base64): {base64.b64encode(encrypted_key).decode()}")
    print("\nCombined Payload (IV.AuthTag.Ciphertext):")
    print(f"{base64.b64encode(iv).decode()}.{base64.b64encode(tag).decode()}.{base64.b64encode(ciphertext).decode()}")


def encrypt_with_js_aes_key(public_key_base64):
    plaintext = input("Enter plaintext to encrypt: ").strip()
    base64_aes_key = input("Enter extracted AES Key (Base64 from JS): ").strip()

    try:
        aes_key = base64.b64decode(base64_aes_key)
        iv = os.urandom(12)
        ciphertext, tag = encrypt_data(plaintext, aes_key, iv)
        payload = (
            base64.b64encode(iv).decode() + '.' +
            base64.b64encode(tag).decode() + '.' +
            base64.b64encode(ciphertext).decode()
        )
        encrypted_aes_key = encrypt_key_with_rsa(aes_key, public_key_base64)
        header_value = base64.b64encode(encrypted_aes_key).decode()

        print("\n--- Final Encrypted Payload ---")
        print("Payload (to be sent in body):")
        print(payload)
        print("\nHeader to be included in request:")
        print(f"X-Api-Encryption-Key: {header_value}")

    except Exception as e:
        print(f"❌ Encryption failed: {e}")


def decryption_mode():
    print("\nPaste response payload in the format: <IV>.<AuthTag>.<Ciphertext>")
    payload = input("Enter Response Payload: ").strip()
    aes_key_b64 = input("Enter AES Key (Base64): ").strip()

    try:
        iv_b64, tag_b64, ciphertext_b64 = payload.split(".")
        aes_key = base64.b64decode(aes_key_b64)
        iv = base64.b64decode(iv_b64 + "===")
        tag = base64.b64decode(tag_b64 + "===")
        ciphertext = base64.b64decode(ciphertext_b64 + "===")

        print(f"\n[INFO] AES key length: {len(aes_key)} bytes")
        print(f"[INFO] IV length: {len(iv)} bytes")
        print(f"[INFO] Auth tag length: {len(tag)} bytes")
        print(f"[INFO] Ciphertext length: {len(ciphertext)} bytes")

        decrypted = decrypt_data(ciphertext, aes_key, iv, tag).decode()
        print("\n✅ Decryption successful!")
        print(f"Decrypted Text:\n{decrypted}")

    except Exception as e:
        print(f"\n❌ Decryption failed: {e}")


def main():
    print("Select mode:")
    print("1 - Encrypt plaintext (new AES key)")
    print("2 - Decrypt response payload")
    print("3 - Encrypt with extracted AES key from JS console")
    choice = input("Enter 1, 2, or 3: ").strip()

    public_key_base64 = "**INSERT_PUBLIC_KEY_VALUE FROM BROWSER CONSOLE OR RESPONSE FROM SERVER**"

    if choice == "1":
        encryption_mode(public_key_base64)
    elif choice == "2":
        decryption_mode()
    elif choice == "3":
        encrypt_with_js_aes_key(public_key_base64)
    else:
        print("Invalid selection.")


if __name__ == "__main__":
    main()
