from dataclasses import dataclass, field
from datetime import datetime

MAGIC = b"GnomeKeyring\n\r\x00\n"
MAGIC_SIZE = 16
NULL_STRING = 0xFFFFFFFF


@dataclass
class KeyringHeader:
    version_major: int
    version_minor: int
    crypto_type: int
    hash_type: int
    kdf_iterations: int
    kdf_salt: bytes


@dataclass
class DecryptedAttribute:
    name: str
    type_id: int  # 0 = string, 1 = int
    value: str | int


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
    filepath: str
    header: KeyringHeader
    hashed_item_ids: list[int]
    encrypted_blob: bytes

    decrypted_items: list[DecryptedItem] | None = None
    decryption_ok: bool = False
