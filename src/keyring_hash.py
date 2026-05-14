from src.keyring_models import KeyringFile


class KeyringHashGenerator:
    def __init__(self, keyring_file: KeyringFile) -> None:
        self.keyring = keyring_file

    def generate_john_hash(self):
        salt_hex = self.keyring.header.kdf_salt.hex()
        iterations = self.keyring.header.kdf_iterations
        blob = self.keyring.encrypted_blob
        crypto_size = len(blob)
        blob_hex = blob.hex()
        filename = "keyring"
        return f"{filename}:$keyring${salt_hex}*{iterations}*{crypto_size}*0*{blob_hex}"
