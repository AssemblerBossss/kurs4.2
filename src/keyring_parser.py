from typing import Any, Optional
from src.binary_reader import BinaryReader
from src.keyring_models import (
    MAGIC, MAGIC_SIZE,
    NULL_STRING,
    KeyringHeader,
    HashedAttribute,
    HashedItem,
    KeyringFile,
    FieldOffset,
)

class KeyringParser:
    """Парсер файла .keyring — извлекает структурированные данные без вывода."""

    def __init__(self, filepath: str):
        with open(filepath, "rb") as f:
            self.data = f.read()
        self.reader = BinaryReader(self.data)

        self.filepath: str = filepath

        # Блок 1: Сигнатура
        self.magic: Optional[bytes] = None

        # Блок 2: Флаги алгоритмов
        self.version_major: Optional[int] = None
        self.version_minor: Optional[int] = None
        self.crypto_type: Optional[int] = None
        self.hash_type: Optional[int] = None

        # Блок 3: Метаданные
        self.name_len: Optional[int] = None
        self.name: Optional[str] = None
        self.ctime: Optional[float] = None
        self.mtime: Optional[float] = None
        self.flags: Optional[int] = None
        self.lock_timeout: Optional[int] = None

        # Блок 4: KDF параметры
        self.kdf_iterations: Optional[int] = None
        self.kdf_salt: Optional[bytes] = None
        self.kdf_reserved: Optional[bytes] = None

        # Блок 5: Hashed items
        self.num_items: Optional[int] = None
        self.hashed_items: list[dict[str, Any]] = []

        # Блок 6: Зашифрованный блок
        self.encrypted_size: Optional[int] = None
        self.encrypted_data: Optional[bytes] = None

        # Смещения всех полей (для визуализатора)
        self.offsets: dict[str, int] = {}

    def parse_magic(self) -> bytes:
        """Извлекает сигнатуру (16 байт)."""
        self.magic = self.reader.read_bytes(16)
        return self.magic

    def parse_version_and_flags(self) -> tuple[int, int, int, int]:
        """Извлекает major, minor, crypto, hash."""
        self.version_major = self.reader.read_u8()
        self.version_minor = self.reader.read_u8()
        self.crypto_type = self.reader.read_u8()
        self.hash_type = self.reader.read_u8()
        return (
            self.version_major,
            self.version_minor,
            self.crypto_type,
            self.hash_type,
        )

    def parse_metadata(self) -> dict[str, Any]:
        """Извлекает метаданные хранилища."""
        name_len = self.reader.read_u32()
        self.name = self.reader.read_bytes(name_len).decode("utf-8", errors="replace")
        self.ctime = self.reader.read_time()
        self.mtime = self.reader.read_time()
        self.flags = self.reader.read_u32()
        self.lock_timeout = self.reader.read_u32()

        return {
            "name": self.name,
            "ctime": self.ctime,
            "mtime": self.mtime,
            "flags": self.flags,
            "lock_timeout": self.lock_timeout,
        }

    def parse_kdf_params(self) -> dict[str, Any]:
        """Извлекает параметры KDF."""
        # HASH_ITERATIONS
        iter_start = self.reader.tell()
        self.kdf_iterations = self.reader.read_u32()
        self.offsets["kdf_iter_start"] = iter_start
        self.offsets["kdf_iter_end"] = self.reader.tell()

        # SALT (8 байт)
        salt_start = self.reader.tell()
        self.kdf_salt = self.reader.read_bytes(8)
        self.offsets["kdf_salt_start"] = salt_start
        self.offsets["kdf_salt_end"] = self.reader.tell()

        # RESERVED[4] (16 байт)
        reserved_start = self.reader.tell()
        self.kdf_reserved = self.reader.read_bytes(16)
        self.offsets["kdf_reserved_start"] = reserved_start
        self.offsets["kdf_reserved_end"] = self.reader.tell()

        return {
            "iterations": self.kdf_iterations,
            "salt": self.kdf_salt,
            "reserved": self.kdf_reserved,
        }

    def parse_hashed_items(self) -> list[dict[str, Any]]:
        """Извлекает hashed items (незашифрованные атрибуты)."""
        # NUM_ITEMS
        num_items_start = self.reader.tell()
        self.num_items = self.reader.read_u32()
        self.offsets["num_items_start"] = num_items_start
        self.offsets["num_items_end"] = self.reader.tell()

        self.hashed_items = []

        for idx in range(self.num_items):
            item_data = {"idx": idx, "offsets": {}, "attributes": []}

            # ITEM ID
            id_start = self.reader.tell()
            item_data["id"] = self.reader.read_u32()
            item_data["offsets"]["id_start"] = id_start
            item_data["offsets"]["id_end"] = self.reader.tell()

            # ITEM TYPE
            type_start = self.reader.tell()
            item_data["type"] = self.reader.read_u32()
            item_data["offsets"]["type_start"] = type_start
            item_data["offsets"]["type_end"] = self.reader.tell()

            # NUM_ATTRS
            num_attrs_start = self.reader.tell()
            num_attrs = self.reader.read_u32()
            item_data["num_attrs"] = num_attrs
            item_data["offsets"]["num_attrs_start"] = num_attrs_start
            item_data["offsets"]["num_attrs_end"] = self.reader.tell()

            # Атрибуты
            for ai in range(num_attrs):
                attr_data = {"idx": ai, "offsets": {}}

                # ATTR NAME (guint32 len + bytes)
                name_len_start = self.reader.tell()
                name_len = self.reader.read_u32()
                attr_data["offsets"]["name_start"] = name_len_start

                name_start = self.reader.tell()
                name_bytes = self.reader.read_bytes(name_len)
                attr_data["name"] = name_bytes.decode("utf-8", errors="replace")
                attr_data["offsets"]["name_end"] = self.reader.tell()

                # ATTR TYPE
                type_start = self.reader.tell()
                attr_data["type"] = self.reader.read_u32()
                attr_data["offsets"]["type_start"] = type_start
                attr_data["offsets"]["type_end"] = self.reader.tell()

                # ATTR HASH (зависит от типа)
                hash_start = self.reader.tell()
                if attr_data["type"] == 0:  # string hash
                    hash_len = self.reader.read_u32()
                    attr_data["hash_len"] = hash_len
                    hash_bytes = self.reader.read_bytes(hash_len)
                    attr_data["hash_str"] = hash_bytes.decode("utf-8", errors="replace")
                    attr_data["hash_int"] = None
                else:  # int hash
                    attr_data["hash_len"] = 4
                    attr_data["hash_int"] = self.reader.read_u32()
                    attr_data["hash_str"] = None

                attr_data["offsets"]["hash_start"] = hash_start
                attr_data["offsets"]["hash_end"] = self.reader.tell()

                item_data["attributes"].append(attr_data)

            self.hashed_items.append(item_data)

        return self.hashed_items

    def parse_encrypted_block(self) -> dict[str, Any]:
        """Извлекает зашифрованный блок."""
        # NUM_ENCRYPTED (размер зашифрованного блока)
        enc_size_start = self.reader.tell()
        self.encrypted_size = self.reader.read_u32()
        self.offsets["encrypted_size_start"] = enc_size_start
        self.offsets["encrypted_size_end"] = self.reader.tell()

        # Зашифрованные данные
        if self.encrypted_size > 0:
            enc_data_start = self.reader.tell()
            self.encrypted_data = self.reader.read_bytes(self.encrypted_size)
            self.offsets["encrypted_data_start"] = enc_data_start
            self.offsets["encrypted_data_end"] = self.reader.tell()
        else:
            self.encrypted_data = b""
            self.offsets["encrypted_data_start"] = self.reader.tell()
            self.offsets["encrypted_data_end"] = self.reader.tell()

        return {
            "size": self.encrypted_size,
            "data": self.encrypted_data,
        }

    def parse_all(self) -> dict[str, Any]:
        """Извлекает все данные последовательно."""
        result = {
            "magic": self.parse_magic(),
            "version": self.parse_version_and_flags(),
            "metadata": self.parse_metadata(),
            "kdf_params": self.parse_kdf_params(),
            "hashed_items": self.parse_hashed_items(),
            "encrypted_block": self.parse_encrypted_block(),
            "file_size": len(self.data),
        }

        # Сохраняем общий размер файла в offsets
        self.offsets["file_end"] = len(self.data)

        return result

    def get_raw_bytes(self, start: int, end: int) -> bytes:
        """Возвращает сырые байты для указанного диапазона."""
        return self.data[start:end]

    def get_current_offset(self) -> int:
        """Возвращает текущую позицию в файле."""
        return self.reader.tell()
