"""
keyring_crypto.py — Криптографические операции для GNOME Keyring

Содержит:
- KDF (Key Derivation Function) — SHA-256 итерационный
- AES-128-CBC расшифровку
- PKCS7 паддинг
- Верификацию через MD5
- Расшифровку записей
"""

import hashlib
import sys

from src.keyring_models import KeyringFile, DecryptedItem, DecryptedAttribute


def derive_key(password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    """
    Деривация ключа и IV по методу GNOME Keyring.

    Формула:
        h0 = SHA-256(password_utf8 || salt)
        hi = SHA-256(h_{i-1})   для i = 1 … iterations-1
        key = h[0:16]
        iv  = h[16:32]

    Args:
        password: Мастер-пароль пользователя
        salt: Соль из файла (8 байт)
        iterations: Количество итераций

    Returns:
        (key, iv) — 16 байт ключ, 16 байт вектор инициализации
    """

    # Начальное значение: SHA-256(password || salt)
    h = hashlib.sha256(password.encode("utf8") + salt).digest()
    for _ in range(iterations - 1):
        h = hashlib.sha256(h).digest()

    # Первые 16 байт — ключ, следующие 16 — IV
    return h[:16], h[16:32]


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Снимает PKCS7-паддинг с проверкой корректности.
    Args:
        data: Данные с паддингом
    """
    if not data:
        raise ValueError("Пустой блок данных при снятии паддинга")

    pad_len = data[-1]

    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"Некорректный паддинг: {pad_len} (должен быть 1-16)")

    # Проверяем, что все байты паддинга совпадают
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("PKCS7: паддинг не совпадает")

    return data[:-pad_len]


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Расшифровка AES-128-CBC.

    Args:
        ciphertext: Зашифрованные данные
        key: 16-байтный ключ
        iv: 16-байтный вектор инициализации

    Returns:
        Расшифрованные данные (с паддингом)
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        raise ImportError(
            "Не установлен pycryptodome. Установите: pip install pycryptodome"
        )

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
    """
    Разбирает plaintext зашифрованного блока в список записей.

    Формат одной записи (все поля big-endian):
        - display_name: guint32 length + UTF-8 bytes
        - secret:       guint32 length + UTF-8 bytes
        - ctime:        guint64 (2 × guint32)
        - mtime:        guint64 (2 × guint32)
        - reserved_str: guint32 length + bytes (обычно пустая)
        - reserved_int: guint32[4] (4 зарезервированных числа)
        - num_attrs:    guint32
        - атрибуты:     для каждого атрибута:
            - name:  guint32 length + bytes
            - type:  guint32 (0=string, 1=int)
            - value: string (guint32+bytes) или int (guint32)
        - acl_len:      guint32
        - ACL записи:   для каждого элемента ACL (пропускаем)

    Args:
        data: Расшифрованные данные (без MD5)
        num_items: Ожидаемое количество записей (из hashed section)

    Returns:
        Список расшифрованных записей
    """
    from src.binary_reader import BinaryReader

    r = BinaryReader(data)
    items = []

    for _ in range(num_items):
        # Основные поля
        display_name = r.read_string() or ""
        secret = r.read_string() or ""
        ctime = r.read_time()
        mtime = r.read_time()

        # Зарезервированные поля (пропускаем)
        _reserved_str = r.read_string()
        _reserved_int = [r.read_u32() for _ in range(4)]

        # Атрибуты
        num_attrs = r.read_u32()
        attrs = []
        for _ in range(num_attrs):
            aname = r.read_string() or ""
            atype = r.read_u32()

            if atype == 0:
                aval: str | int = r.read_string() or ""
            else:
                aval = r.read_u32()

            attrs.append(DecryptedAttribute(aname, atype, aval))

        # ACL (Access Control List) — пропускаем
        acl_len = r.read_u32()
        for _ in range(acl_len):
            r.read_u32()  # types_allowed
            r.read_string()  # display_name
            r.read_string()  # pathname
            r.read_string()  # reserved
            r.read_u32()  # reserved int

        items.append(
            DecryptedItem(
                item_id=0,  # временно, потом заполним из hashed_items
                display_name=display_name,
                secret=secret,
                ctime=ctime,
                mtime=mtime,
                attributes=attrs,
            )
        )

    return items


def decrypt_keyring(keyring: KeyringFile, password: str, verbose: bool = False) -> bool:
    header = keyring.header
    key, iv = derive_key(password, header.kdf_salt, header.kdf_iterations)

    try:
        raw = aes_decrypt(keyring.encrypted_blob, key, iv)
    except Exception:
        keyring.decryption_ok = False
        return False

    # Убираем pkcs7_unpad — GNOME Keyring использует нулевой паддинг
    # MD5 считается от всего блока включая нули
    ok, plaintext = verify_decryption(raw)
    if not ok:
        keyring.decryption_ok = False
        return False

    try:
        items = parse_decrypted_items(plaintext, len(keyring.hashed_items))
        for i, item in enumerate(items):
            if i < len(keyring.hashed_items):
                item.item_id = keyring.hashed_items[i].item_id
        keyring.decrypted_items = items
        keyring.decryption_ok = True
        return True
    except Exception as e:
        if verbose:
            print(f"[!] parse error: {e}", file=sys.stderr)
        keyring.decryption_ok = False
        return False
