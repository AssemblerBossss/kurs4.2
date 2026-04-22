"""
keyring_models.py — Структуры данных для работы с GNOME Keyring

Содержит dataclass'ы для представления всех компонентов .keyring файла:
- Заголовок (метаданные, KDF параметры)
- Хешированные записи (незашифрованные атрибуты)
- Расшифрованные записи (полные данные)
"""

from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import datetime

# ─── Константы ────────────────────────────────────────────────────────────────

MAGIC = b"GnomeKeyring\n\r\x00\n"
MAGIC_SIZE = 16

CRYPTO_AES = 0
CRYPTO_NONE = 1
CRYPTO_NAMES = {
    CRYPTO_AES: "AES-128-CBC",
    CRYPTO_NONE: "NONE (незашифрован)",
}

HASH_SHA256 = 0
HASH_NONE = 1
HASH_NAMES = {
    HASH_SHA256: "SHA-256 (итерационный KDF)",
    HASH_NONE: "NONE",
}

# Sentinel-значение для отсутствующей строки
NULL_STRING = 0xFFFFFFFF


@dataclass
class FieldOffset:
    """Смещение поля в файле (для визуализации)."""

    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class KeyringHeader:
    """Заголовок файла .keyring (блоки 1-4)."""

    # Блок 1: Сигнатура
    magic: bytes

    # Блок 2: Флаги алгоритмов
    version_major: int
    version_minor: int
    crypto_type: int
    hash_type: int

    # Блок 3: Метаданные хранилища
    name: str
    ctime: int  # Unix timestamp (секунды)
    mtime: int  # Unix timestamp (секунды)
    flags: int
    lock_timeout: int

    # Блок 4: Параметры KDF
    kdf_iterations: int
    kdf_salt: bytes  # 8 байт
    kdf_reserved: bytes  # 16 байт, должны быть нулями

    # Смещения (для визуализации)
    offsets: dict[str, FieldOffset] = field(default_factory=dict)

    @property
    def crypto_name(self) -> str:
        return CRYPTO_NAMES.get(self.crypto_type, f"Unknown({self.crypto_type})")

    @property
    def hash_name(self) -> str:
        return HASH_NAMES.get(self.hash_type, f"Unknown({self.hash_type})")

    @property
    def ctime_str(self) -> str:
        if self.ctime == 0:
            return "не задано"
        return datetime.fromtimestamp(self.ctime).strftime("%Y-%m-%d %H:%M:%S")

    @property
    def mtime_str(self) -> str:
        if self.mtime == 0:
            return "не задано"
        return datetime.fromtimestamp(self.mtime).strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class HashedAttribute:
    """Атрибут записи в незашифрованном разделе (только хеш значения)."""

    name: str
    type_id: int  # 0 = string, 1 = int
    hash_str: Optional[str] = None  # для строк: hex-строка (32 байта)
    hash_int: Optional[int] = None  # для чисел: 4-байтовое значение
    offsets: dict[str, FieldOffset] = field(default_factory=dict)

    @property
    def hash_hex(self) -> str:
        if self.type_id == 0 and self.hash_str:
            return self.hash_str
        elif self.type_id == 1 and self.hash_int is not None:
            return f"{self.hash_int:08x}"
        return ""

    @property
    def type_name(self) -> str:
        return "string" if self.type_id == 0 else "int"


@dataclass
class HashedItem:
    """Запись в незашифрованном разделе (хешированные атрибуты)."""

    idx: int  # порядковый номер (0..N-1)
    item_id: int  # уникальный идентификатор записи
    item_type: int  # тип записи
    attributes: list[HashedAttribute]
    offsets: dict[str, FieldOffset] = field(default_factory=dict)


# ─── Структуры для расшифрованных данных ─────────────────────────────────────


@dataclass
class DecryptedAttribute:
    """Атрибут записи с расшифрованным значением."""

    name: str
    type_id: int  # 0 = string, 1 = int
    value: str | int

    @property
    def type_name(self) -> str:
        return "string" if self.type_id == 0 else "int"


@dataclass
class DecryptedItem:
    """Полностью расшифрованная запись хранилища."""

    item_id: int
    display_name: str
    secret: str
    ctime: int
    mtime: int
    attributes: list[DecryptedAttribute] = field(default_factory=list)

    @property
    def ctime_str(self) -> str:
        if self.ctime == 0:
            return "не задано"
        return datetime.fromtimestamp(self.ctime).strftime("%Y-%m-%d %H:%M:%S")

    @property
    def mtime_str(self) -> str:
        if self.mtime == 0:
            return "не задано"
        return datetime.fromtimestamp(self.mtime).strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class KeyringFile:
    """Полностью разобранный .keyring файл."""

    filepath: str
    file_size: int
    header: KeyringHeader
    hashed_items: list[HashedItem]
    encrypted_blob: bytes  # сырой зашифрованный блок

    # Заполняется после расшифровки
    decrypted_items: Optional[list[DecryptedItem]] = None
    decryption_ok: bool = False

    @property
    def encrypted_size(self) -> int:
        return len(self.encrypted_blob)

    @property
    def has_encrypted_data(self) -> bool:
        return self.encrypted_size > 0
