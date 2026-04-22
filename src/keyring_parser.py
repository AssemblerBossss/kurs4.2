from typing import Any, Optional
from src.binary_reader import BinaryReader


class KeyringParser:
    """Парсер файла .keyring — извлекает структурированные данные без вывода."""

    def __init__(self, filepath: str):
        with open(filepath, "rb") as f:
            self.data = f.read()
        self.reader = BinaryReader(self.data)

        self.filepath:      str = filepath
        self.magic:         Optional[bytes] = None
        self.version_major: Optional[int] = None
        self.version_minor: Optional[int] = None
        self.crypto_type:   Optional[int] = None
        self.hash_type:     Optional[int] = None
        self.name:          Optional[str] = None
        self.ctime:         Optional[float] = None
        self.mtime:         Optional[float] = None
        self.flags:         Optional[int] = None
        self.lock_timeout:  Optional[int] = None

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

    def parse_all(self) -> dict[str, Any]:
        """Извлекает все данные последовательно."""
        return {
            "magic": self.parse_magic(),
            "version": self.parse_version_and_flags(),
            "metadata": self.parse_metadata(),
            "file_size": len(self.data),
        }

    def get_raw_bytes(self, start: int, end: int) -> bytes:
        """Возвращает сырые байты для указанного диапазона."""
        return self.data[start:end]

    def get_current_offset(self) -> int:
        """Возвращает текущую позицию в файле."""
        return self.reader.tell()
