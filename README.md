# CRYPTOGRAPHY
# Hashing, Digital Signature & Vehicle Registration (Console)
npm install
npm start

## Setup & run
    pip install -r requirements.txt
    python3 app.py

## Features
1. **SHA-256 hash** of any text message (hashlib).
2. **Digital signature**: generates an RSA-2048 key pair, signs a message with the private key (RSA-PSS + SHA-256), verifies with the public key and reports valid/invalid. Enter a different message at the verify step to see a failed verification.
3. **Vehicle registration**: store (plate, owner, model) in a dictionary and retrieve by plate. Duplicate plates are rejected (case-insensitive); unknown plates show an error.
4. """Menu-driven console app:
  1. SHA-256 hashing
  2. Digital signature (RSA key pair, sign + verify)
  3. Vehicle registration system (store / get)
"""

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ------------------------- 1. SHA-256 hashing ------------------------------
def sha256_hash(message: str) -> str:
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


# ------------------------- 2. Digital signature ----------------------------
class SignatureManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    @staticmethod
    def _pss():
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        )

    def sign(self, message: str) -> bytes:
        return self.private_key.sign(message.encode("utf-8"), self._pss(), hashes.SHA256())

    def verify(self, message: str, signature: bytes) -> bool:
        try:
            self.public_key.verify(
                signature, message.encode("utf-8"), self._pss(), hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


# ------------------------- 3. Vehicle registration -------------------------
class VehicleRegistry:
    def __init__(self):
        self.vehicles: dict[str, dict] = {}

    @staticmethod
    def _normalize(plate: str) -> str:
        return plate.strip().upper()

    def register(self, plate: str, owner: str, model: str) -> str:
        plate = self._normalize(plate)
        if not plate or not owner.strip() or not model.strip():
            return "ERROR: number plate, owner and model cannot be empty."
        if plate in self.vehicles:
            return f"ERROR: number plate '{plate}' is already registered."
        self.vehicles[plate] = {"owner": owner.strip(), "model": model.strip()}
        return f"Vehicle '{plate}' registered successfully."

    def get(self, plate: str):
        return self.vehicles.get(self._normalize(plate))


# ------------------------- Console UI --------------------------------------
def show_menu() -> None:
    print("\n========== Main Menu ==========")
    print("1. Generate SHA-256 hash")
    print("2. Digital signature (generate keys, sign & verify)")
    print("3. Register vehicle")
    print("4. Get vehicle details")
    print("5. Exit")


def handle_signature(sig: SignatureManager) -> None:
    sig.generate_keys()
    print("\nNew RSA key pair generated.")
    print("Public key:\n" + sig.public_key_pem())

    message = input("Enter message to sign: ")
    signature = sig.sign(message)
    print(f"Signature (hex): {signature.hex()}")

    verify_msg = input(
        "Enter message to verify (press Enter to reuse the same message): "
    )
    if verify_msg == "":
        verify_msg = message
    if sig.verify(verify_msg, signature):
        print("Signature is VALID.")
    else:
        print("Signature is INVALID (message does not match the signature).")


def main() -> None:
    sig = SignatureManager()
    registry = VehicleRegistry()

    while True:
        show_menu()
        try:
            choice = input("Choose an option (1-5): ").strip()

            if choice == "1":
                message = input("Enter message: ")
                print(f"SHA-256: {sha256_hash(message)}")

            elif choice == "2":
                handle_signature(sig)

            elif choice == "3":
                plate = input("Number plate: ")
                owner = input("Owner name: ")
                model = input("Model: ")
                print(registry.register(plate, owner, model))

            elif choice == "4":
                plate = input("Number plate: ")
                vehicle = registry.get(plate)
                if vehicle is None:
                    print(f"ERROR: no vehicle found with number plate '{plate.strip().upper()}'.")
                else:
                    print(f"Owner: {vehicle['owner']}")
                    print(f"Model: {vehicle['model']}")

            elif choice == "5":
                print("Goodbye!")
                break

            else:
                print("Invalid choice. Please enter a number from 1 to 5.")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break


if __name__ == "__main__":
    main()

