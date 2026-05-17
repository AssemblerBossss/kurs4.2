from dataclasses import dataclass, field
from datetime import datetime

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

NULL_STRING = 0xFFFFFFFF


@dataclass
class FieldOffset:
    start: int
    end: int


@dataclass
class KeyringHeader:
    magic: bytes

    version_major: int
    version_minor: int
    crypto_type: int
    hash_type: int

    name: str
    ctime: int
    mtime: int
    flags: int
    lock_timeout: int

    kdf_iterations: int
    kdf_salt: bytes
    kdf_reserved: bytes

    offsets: dict[str, FieldOffset] = field(default_factory=dict)

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
    name: str
    type_id: int  # 0 = string, 1 = int
    hash_str: str | None = None
    hash_int: int | None = None
    offsets: dict[str, FieldOffset] = field(default_factory=dict)

    @property
    def hash_hex(self) -> str:
        if self.type_id == 0 and self.hash_str:
            return self.hash_str
        elif self.type_id == 1 and self.hash_int is not None:
            return f"{self.hash_int:08x}"
        return ""


@dataclass
class HashedItem:
    idx: int
    item_id: int
    item_type: int
    attributes: list[HashedAttribute]
    offsets: dict[str, FieldOffset] = field(default_factory=dict)


@dataclass
class DecryptedAttribute:
    name: str
    type_id: int  # 0 = string, 1 = int
    value: str | int

    @property
    def type_name(self) -> str:
        return "string" if self.type_id == 0 else "int"


@dataclass
class DecryptedItem:
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
    data: bytes = field(repr=False)
    filepath: str
    file_size: int
    header: KeyringHeader
    hashed_items: list[HashedItem]
    encrypted_blob: bytes

    decrypted_items: list[DecryptedItem] | None = None
    decryption_ok: bool = False

    @property
    def encrypted_size(self) -> int:
        return len(self.encrypted_blob)
