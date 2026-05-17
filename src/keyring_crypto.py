import hashlib
from Crypto.Cipher import AES

from src.keyring_models import KeyringFile, DecryptedItem, DecryptedAttribute
from src.keyring_parser import BinaryReader


def derive_key(password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    h = hashlib.sha256(password.encode("utf8") + salt).digest()
    for _ in range(iterations - 1):
        h = hashlib.sha256(h).digest()
    return h[:16], h[16:32]


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)


def verify_decryption(plaintext_with_hash: bytes) -> tuple[bool, bytes]:
    if len(plaintext_with_hash) < 16:
        return False, b""
    expected_hash = plaintext_with_hash[:16]
    raw_plaintext = plaintext_with_hash[16:]
    actual_hash = hashlib.md5(raw_plaintext).digest()

    return expected_hash == actual_hash, raw_plaintext


def parse_decrypted_items(data: bytes, num_items: int) -> list[DecryptedItem]:
    reader = BinaryReader(data)
    decrypted_items = []

    for item_index in range(num_items):
        display_name = reader.read_string() or ""
        secret_raw = reader.read_byte_array() or ""
        try:
            secret = secret_raw.decode("utf-8")
        except UnicodeDecodeError:
            secret = secret_raw.hex()

        creation_time = reader.read_time()
        modification_time = reader.read_time()

        reader.read_string()
        for _ in range(4):
            reader.read_u32()

        attributes_count = reader.read_u32()
        attributes = []

        for _ in range(attributes_count):
            attribute_name = reader.read_string() or ""
            attribute_type = reader.read_u32()  # 0 = строка, 1 = число

            if attribute_type == 0:
                attribute_value: str | int = reader.read_string() or ""
            else:
                attribute_value = reader.read_u32()

            attributes.append(
                DecryptedAttribute(attribute_name, attribute_type, attribute_value)
            )

        acl_entries_count = reader.read_u32()

        for _ in range(acl_entries_count):
            reader.read_u32()  # allowed_access_types (битовая маска разрешений)
            reader.read_string()  # application_display_name (имя приложения)
            reader.read_string()  # application_path (путь к приложению)
            reader.read_string()  # reserved_string (зарезервировано)
            reader.read_u32()  # reserved_integer (зарезервировано)

        decrypted_items.append(
            DecryptedItem(
                item_id=0,
                display_name=display_name,
                secret=secret,
                ctime=creation_time,
                mtime=modification_time,
                attributes=attributes,
            )
        )

    return decrypted_items


def decrypt_keyring(keyring: KeyringFile, password: str) -> bool:
    header = keyring.header
    key, iv = derive_key(password, header.kdf_salt, header.kdf_iterations)
    try:
        raw = aes_decrypt(keyring.encrypted_blob, key, iv)
        ok, plaintext = verify_decryption(raw)
        if not ok:
            raise ValueError("Неверный пароль или повреждённые данные")

        items = parse_decrypted_items(plaintext, len(keyring.hashed_items))
        for i, item in enumerate(items):
            if i < len(keyring.hashed_items):
                item.item_id = keyring.hashed_items[i].item_id

        keyring.decrypted_items = items
        keyring.decryption_ok = True
        return True

    except Exception:
        keyring.decryption_ok = False
        return False
