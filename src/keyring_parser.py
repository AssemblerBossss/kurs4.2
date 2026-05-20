import struct
from src.keyring_models import (
    MAGIC,
    MAGIC_SIZE,
    KeyringHeader,
    KeyringFile,
)


class BinaryReader:
    _NULL_STRING: int = 0xFFFF_FFFF
    _FMT_U8 = struct.Struct(">B")
    _FMT_U32 = struct.Struct(">I")

    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    def read_bytes(self, n: int) -> bytes:
        if self._offset + n > len(self._data):
            raise ValueError(
                f"Неожиданный конец файла: запрошено {n} байт "
                f"по смещению 0x{self._offset:04x}, доступно {len(self._data) - self._offset}"
            )
        chunk = self._data[self._offset : self._offset + n]
        self._offset += n

        return chunk

    def read_u8(self) -> int:
        return self._FMT_U8.unpack(self.read_bytes(1))[0]

    def read_u32(self) -> int:
        return self._FMT_U32.unpack(self.read_bytes(4))[0]

    def read_time(self) -> int:
        hi = self.read_u32()
        lo = self.read_u32()
        return (hi << 32) | lo

    def read_string(self) -> str | None:
        length = self.read_u32()
        if length == self._NULL_STRING:
            return None

        raw = self.read_bytes(length)
        return raw.decode("utf-8", errors="replace")

    def read_byte_array(self) -> bytes | None:
        length = self.read_u32()
        if length == self._NULL_STRING:
            return None
        if length >= 0x7FFFFFFF:
            raise ValueError(f"Некорректная длина byte array: 0x{length:08x}")
        return self.read_bytes(length)


class KeyringParser:
    def __init__(self, filepath: str):
        with open(filepath, "rb") as f:
            self.data = f.read()

        self.reader = BinaryReader(self.data)
        self.filepath: str = filepath

    def _parse_header(self) -> KeyringHeader:
        magic = self.reader.read_bytes(MAGIC_SIZE)
        if magic != MAGIC:
            raise ValueError(
                f"Неверная сигнатура. Ожидалось: {MAGIC!r}, получено: {magic!r}"
            )

        version_major = self.reader.read_u8()
        version_minor = self.reader.read_u8()
        crypto_type = self.reader.read_u8()
        hash_type = self.reader.read_u8()

        if version_major != 0:
            raise ValueError(
                f"Неподдерживаемая версия формата: {version_major}.{version_minor}"
            )

        if crypto_type not in (0, 1):
            raise ValueError(f"Неизвестный тип шифрования: {crypto_type}")

        self.reader.read_string()  # name
        self.reader.read_time()  # ctime
        self.reader.read_time()  # mtime
        self.reader.read_u32()  # flags
        self.reader.read_u32()  # lock_timeout

        iterations = self.reader.read_u32()
        salt = self.reader.read_bytes(8)
        self.reader.read_bytes(16)  # reserved

        return KeyringHeader(
            version_major=version_major,
            version_minor=version_minor,
            crypto_type=crypto_type,
            hash_type=hash_type,
            kdf_iterations=iterations,
            kdf_salt=salt,
        )

    def _skip_hashed_attributes(self, num_attrs: int) -> None:
        for _ in range(num_attrs):
            name_len = self.reader.read_u32()
            self.reader.read_bytes(name_len)
            attr_type = self.reader.read_u32()
            if attr_type == 0:
                hash_len = self.reader.read_u32()
                self.reader.read_bytes(hash_len)
            else:
                self.reader.read_u32()

    def _parse_hashed_item_ids(self) -> list[int]:
        num_items = self.reader.read_u32()
        ids: list[int] = []
        for _ in range(num_items):
            item_id = self.reader.read_u32()
            self.reader.read_u32()
            num_attrs = self.reader.read_u32()
            self._skip_hashed_attributes(num_attrs)
            ids.append(item_id)
        return ids

    def _parse_encrypted_block(self) -> bytes:
        encrypted_size = self.reader.read_u32()
        if encrypted_size == 0:
            return b""
        return self.reader.read_bytes(encrypted_size)

    def parse_all(self) -> KeyringFile:
        header = self._parse_header()
        ids = self._parse_hashed_item_ids()
        encrypted_blob = self._parse_encrypted_block()
        return KeyringFile(
            filepath=self.filepath,
            header=header,
            hashed_item_ids=ids,
            encrypted_blob=encrypted_blob,
        )
