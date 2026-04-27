from src.keyring_models import KeyringFile


class KeyringHashGenerator:
    """Генератор хэшей для инструментов взлома паролей."""

    MAGIC_BYTES = b"GNOME_KEYRING_IDENTIFIER\x00"

    def __init__(self, keyring_file: KeyringFile) -> None:
        self.keyring = keyring_file

    def generate_hash(self, tool: str = "hashcat") -> str:
        """Генерирует хэш для HashCat (mode 23800) или John the Ripper."""

        if not self.keyring.encrypted_blob:
            raise ValueError("Нет зашифрованных данных в keyring файле")

        iterations = self.keyring.header.kdf_iterations
        salt = self.keyring.header.kdf_salt
        encrypted_data = self.keyring.encrypted_blob

        if tool == "hashcat":
            # Формат HashCat (режим 23800)
            # $gnome_keyring$*<iterations_hex>*<salt_hex>*<encrypted_hex>
            return f"$gnome_keyring$*{iterations:x}*{salt.hex()}*{encrypted_data.hex()}"

        elif tool == "john":
            # Формат John the Ripper
            # $gnome-keyring$<iterations_decimal>$<salt_hex>$<encrypted_hex>
            return f"$gnome-keyring${iterations}${salt.hex()}${encrypted_data.hex()}"

        else:
            raise ValueError(
                f"Неизвестный инструмент: {tool}. Используйте 'hashcat' или 'john'"
            )
