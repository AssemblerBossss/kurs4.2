import struct
from typing import Any
from src.keyring_models import (
    MAGIC,
    MAGIC_SIZE,
    NULL_STRING,
    KeyringHeader,
    HashedAttribute,
    HashedItem,
    KeyringFile,
    FieldOffset,
)


class BinaryReader:
    _NULL_STRING: int = 0xFFFF_FFFF
    _FMT_U8 = struct.Struct(">B")  # 1 байт,  unsigned
    _FMT_U32 = struct.Struct(">I")  # 4 байта, unsigned big-endian

    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    def tell(self) -> int:
        return self._offset

    def remaining(self):
        return len(self._data) - self._offset

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

        self._offsets: dict[str, Any] = {}

    def _save_offset(self, name: str, start: int, end: int) -> None:
        self._offsets[name] = FieldOffset(start=start, end=end)

    def _save_offset_pair(self, name: str, start: int) -> None:
        self._save_offset(name, start, self.reader.tell())

    def _parse_magic(self) -> bytes:
        start = self.reader.tell()
        magic = self.reader.read_bytes(MAGIC_SIZE)
        self._save_offset_pair("magic", start)

        if magic != MAGIC:
            raise ValueError(
                f"Неверная сигнатура. Ожидалось: {MAGIC!r}, получено: {magic!r}"
            )

        return magic

    def _parse_version_block(self) -> tuple[int, int, int, int, dict[str, FieldOffset]]:
        """Извлекает major, minor, crypto, hash и их смещения."""
        offsets = {}

        start = self.reader.tell()
        version_major = self.reader.read_u8()
        offsets["version_major"] = FieldOffset(start, self.reader.tell())

        start = self.reader.tell()
        version_minor = self.reader.read_u8()
        offsets["version_minor"] = FieldOffset(start, self.reader.tell())

        start = self.reader.tell()
        crypto_type = self.reader.read_u8()
        offsets["crypto_type"] = FieldOffset(start, self.reader.tell())

        start = self.reader.tell()
        hash_type = self.reader.read_u8()
        offsets["hash_type"] = FieldOffset(start, self.reader.tell())

        if version_major != 0:
            raise ValueError(
                f"Неподдерживаемая версия формата: {version_major}.{version_minor} "
                f"(поддерживается только версия 0, crypto=0, AES-128-CBC)"
            )

        return version_major, version_minor, crypto_type, hash_type, offsets

    def _parse_name(self) -> tuple[str, dict[str, FieldOffset]]:
        offsets = {}

        len_start = self.reader.tell()
        name_len = self.reader.read_u32()
        offsets["name_len"] = FieldOffset(len_start, self.reader.tell())

        name_start = self.reader.tell()
        if name_len == NULL_STRING:
            name = ""
        else:
            name_bytes = self.reader.read_bytes(name_len)
            name = name_bytes.decode("utf-8", errors="replace")
        offsets["name"] = FieldOffset(name_start, self.reader.tell())

        return name, offsets

    def _parse_metadata(self) -> tuple[int, int, int, int, dict[str, FieldOffset]]:
        offsets = {}

        start = self.reader.tell()
        ctime = self.reader.read_time()
        offsets["ctime"] = FieldOffset(start, self.reader.tell())

        start = self.reader.tell()
        mtime = self.reader.read_time()
        offsets["mtime"] = FieldOffset(start, self.reader.tell())

        start = self.reader.tell()
        flags = self.reader.read_u32()
        offsets["flags"] = FieldOffset(start, self.reader.tell())

        start = self.reader.tell()
        lock_timeout = self.reader.read_u32()
        offsets["lock_timeout"] = FieldOffset(start, self.reader.tell())

        return ctime, mtime, flags, lock_timeout, offsets

    def _parse_kdf_params(self) -> tuple[int, bytes, bytes, dict[str, FieldOffset]]:
        offsets = {}

        start = self.reader.tell()
        iterations = self.reader.read_u32()
        offsets["kdf_iterations"] = FieldOffset(start, self.reader.tell())

        start = self.reader.tell()
        salt = self.reader.read_bytes(8)
        offsets["kdf_salt"] = FieldOffset(start, self.reader.tell())

        start = self.reader.tell()
        reserved = self.reader.read_bytes(16)
        offsets["kdf_reserved"] = FieldOffset(start, self.reader.tell())

        return iterations, salt, reserved, offsets

    def _parse_hashed_attributes(
        self, num_attrs: int
    ) -> tuple[list[HashedAttribute], dict]:
        attrs = []
        attrs_offsets = {}

        for ai in range(num_attrs):
            attr_offsets = {}

            name_len_start = self.reader.tell()
            name_len = self.reader.read_u32()
            attr_offsets["name_len"] = FieldOffset(name_len_start, self.reader.tell())

            name_start = self.reader.tell()
            name_bytes = self.reader.read_bytes(name_len)
            name = name_bytes.decode("utf-8", errors="replace")
            attr_offsets["name"] = FieldOffset(name_start, self.reader.tell())

            type_start = self.reader.tell()
            attr_type = self.reader.read_u32()
            attr_offsets["type"] = FieldOffset(type_start, self.reader.tell())

            if attr_type == 0:  # string hash
                hash_len_start = self.reader.tell()
                hash_len = self.reader.read_u32()
                hash_len_end = self.reader.tell()
                attr_offsets["hash_len"] = FieldOffset(hash_len_start, hash_len_end)

                hash_start = self.reader.tell()
                hash_bytes = self.reader.read_bytes(hash_len)
                hash_str = hash_bytes.decode("utf-8", errors="replace")
                hash_end = self.reader.tell()
                attr_offsets["hash"] = FieldOffset(hash_start, hash_end)

                attrs.append(
                    HashedAttribute(
                        name=name,
                        type_id=attr_type,
                        hash_str=hash_str,
                        hash_int=None,
                        offsets=attr_offsets,
                    )
                )
            else:
                hash_start = self.reader.tell()
                hash_int = self.reader.read_u32()
                hash_end = self.reader.tell()
                attr_offsets["hash"] = FieldOffset(hash_start, hash_end)

                attrs.append(
                    HashedAttribute(
                        name=name,
                        type_id=attr_type,
                        hash_str=None,
                        hash_int=hash_int,
                        offsets=attr_offsets,
                    )
                )

            attrs_offsets[f"attr_{ai}"] = attr_offsets

        return attrs, attrs_offsets

    def _parse_hashed_items(self) -> tuple[list[HashedItem], dict]:
        items = []
        items_offsets = {}

        num_items_start = self.reader.tell()
        num_items = self.reader.read_u32()
        self._offsets["num_items"] = FieldOffset(num_items_start, self.reader.tell())

        for idx in range(num_items):
            item_offsets = {}

            id_start = self.reader.tell()
            item_id = self.reader.read_u32()
            item_offsets["id"] = FieldOffset(id_start, self.reader.tell())

            type_start = self.reader.tell()
            item_type = self.reader.read_u32()
            item_offsets["type"] = FieldOffset(type_start, self.reader.tell())

            num_attrs_start = self.reader.tell()
            num_attrs = self.reader.read_u32()
            item_offsets["num_attrs"] = FieldOffset(num_attrs_start, self.reader.tell())

            attrs, attrs_offsets = self._parse_hashed_attributes(num_attrs)
            item_offsets["attributes"] = attrs_offsets

            items.append(
                HashedItem(
                    idx=idx,
                    item_id=item_id,
                    item_type=item_type,
                    attributes=attrs,
                    offsets=item_offsets,
                )
            )
            items_offsets[f"item_{idx}"] = item_offsets

        return items, items_offsets

    def _parse_encrypted_block(self) -> tuple[bytes, dict]:
        offsets = {}

        size_start = self.reader.tell()
        encrypted_size = self.reader.read_u32()
        offsets["encrypted_size"] = FieldOffset(size_start, self.reader.tell())

        if encrypted_size > 0:
            data_start = self.reader.tell()
            encrypted_data = self.reader.read_bytes(encrypted_size)
            offsets["encrypted_data"] = FieldOffset(data_start, self.reader.tell())
        else:
            encrypted_data = b""
            offsets["encrypted_data"] = FieldOffset(
                self.reader.tell(), self.reader.tell()
            )

        return encrypted_data, offsets

    def parse_all(self) -> KeyringFile:
        magic = self._parse_magic()

        ver_major, ver_minor, crypto, hash_type, version_offsets = (
            self._parse_version_block()
        )
        self._offsets.update(version_offsets)

        name, name_offsets = self._parse_name()
        self._offsets.update(name_offsets)

        ctime, mtime, flags, lock_timeout, meta_offsets = self._parse_metadata()
        self._offsets.update(meta_offsets)

        iterations, salt, reserved, kdf_offsets = self._parse_kdf_params()
        self._offsets.update(kdf_offsets)

        hashed_items, items_offsets = self._parse_hashed_items()
        self._offsets["hashed_items"] = items_offsets

        encrypted_data, enc_offsets = self._parse_encrypted_block()
        self._offsets.update(enc_offsets)

        self._offsets["file_end"] = FieldOffset(len(self.data), len(self.data))

        header = KeyringHeader(
            magic=magic,
            version_major=ver_major,
            version_minor=ver_minor,
            crypto_type=crypto,
            hash_type=hash_type,
            name=name,
            ctime=ctime,
            mtime=mtime,
            flags=flags,
            lock_timeout=lock_timeout,
            kdf_iterations=iterations,
            kdf_salt=salt,
            kdf_reserved=reserved,
            offsets=self._offsets,
        )

        return KeyringFile(
            filepath=self.filepath,
            file_size=len(self.data),
            data=self.data,
            header=header,
            hashed_items=hashed_items,
            encrypted_blob=encrypted_data,
        )
