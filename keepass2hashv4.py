#!/usr/bin/env python3

import sys
import struct
import hashlib
import os


# --- Constants ---

FILE_SIGNATURE1 = 0x9AA2D903
FILE_SIGNATURE2 = 0xB54BFB67

FILE_SIGNATURE_PRE1 = 0x9AA2D903
FILE_SIGNATURE_PRE2 = 0xB54BFB66

FILE_VERSION_MASK = 0xFFFF0000
FILE_VERSION_4 = 0x00040000


# --- Binary Helpers ---

def read_u32(f):
    return struct.unpack("<I", f.read(4))[0]


def read_u16(f):
    return struct.unpack("<H", f.read(2))[0]


def read_bytes(f, n):
    b = f.read(n)
    if len(b) != n:
        raise ValueError("Unexpected EOF")
    return b


def bytes_to_int(b):
    return int.from_bytes(b, "little")


# --- VariantDictionary Parser (KDBX 4) ---

def parse_variant_dictionary(data):
    pos = 0

    version = bytes_to_int(data[pos:pos+2])
    pos += 2

    if (version >> 8) != 1:
        raise ValueError("Unsupported VariantDictionary version")

    result = {}

    while pos < len(data):
        t = data[pos]
        pos += 1

        if t == 0:
            break

        key_len = bytes_to_int(data[pos:pos+4])
        pos += 4

        key = data[pos:pos+key_len].decode()
        pos += key_len

        value_len = bytes_to_int(data[pos:pos+4])
        pos += 4

        value = data[pos:pos+value_len]
        pos += value_len

        result[key] = (t, value)

    return result


# --- Main Parser ---

def process_database(filename):

    with open(filename, "rb") as f:

        sig1 = read_u32(f)
        sig2 = read_u32(f)

        if not (
            (sig1 == FILE_SIGNATURE1 and sig2 == FILE_SIGNATURE2) or
            (sig1 == FILE_SIGNATURE_PRE1 and sig2 == FILE_SIGNATURE_PRE2)
        ):
            print("Invalid KeePass file")
            return

        version = read_u32(f)
        kdbx_version = version >> 16

        master_seed = None
        transform_seed = None
        iv = None
        expected_start = None
        transform_rounds = 0
        algorithm = 0

        # KDBX4 Argon2 parameters
        kdf_uuid = 0
        argon2_m = 0
        argon2_v = 0
        argon2_p = 0

        # --- Read Header ---
        while True:

            field_id_raw = f.read(1)
            if not field_id_raw:
                raise ValueError("Unexpected EOF in header")

            field_id = field_id_raw[0]

            if version < FILE_VERSION_4:
                size = read_u16(f)
            else:
                size = read_u32(f)

            data = read_bytes(f, size) if size > 0 else b""

            if field_id == 0:
                break

            elif field_id == 4:  # MasterSeed
                master_seed = data

            elif field_id == 5:  # TransformSeed (KDBX3)
                transform_seed = data

            elif field_id == 6:  # TransformRounds (KDBX3)
                transform_rounds = bytes_to_int(data)

            elif field_id == 7:  # EncryptionIV
                iv = data

            elif field_id == 9:  # StreamStartBytes (KDBX3)
                expected_start = data

            elif field_id == 2:  # CipherID
                if data.startswith(b"\x31\xc1\xf2\xe6"):
                    algorithm = 0  # AES
                elif data.startswith(b"\xad\x68\xf2\x9f"):
                    algorithm = 1  # Twofish
                elif data.startswith(b"\xd6\x03\x8a\x2b"):
                    algorithm = 2  # ChaCha20

            elif field_id == 11:  # KdfParameters (KDBX4)

                vd = parse_variant_dictionary(data)

                for key, (t, val) in vd.items():

                    if key == "S":
                        transform_seed = val

                    elif key in ("R", "I"):
                        transform_rounds = bytes_to_int(val)

                    elif key == "M":
                        argon2_m = bytes_to_int(val)

                    elif key == "V":
                        argon2_v = bytes_to_int(val)

                    elif key == "P":
                        argon2_p = bytes_to_int(val)

                    elif key == "$UUID":
                        # Big endian
                        kdf_uuid = struct.unpack(">I", val[:4])[0]

        dbname = os.path.splitext(os.path.basename(filename))[0]

        # --- KDBX 3.x ---
        if kdbx_version < 4:

            encrypted_start = read_bytes(f, 32)

            print(
                f"{dbname}:$keepass$*2*{transform_rounds}*{algorithm}*"
                f"{master_seed.hex()}*"
                f"{transform_seed.hex()}*"
                f"{iv.hex()}*"
                f"{expected_start.hex()}*"
                f"{encrypted_start.hex()}"
            )

        # --- KDBX 4.x ---
        else:

            header_end = f.tell()

            f.seek(0)
            header = read_bytes(f, header_end)

            calc_hash = hashlib.sha256(header).digest()
            stored_hash = read_bytes(f, 32)
            header_hmac = read_bytes(f, 32)

            if calc_hash != stored_hash:
                print("Warning: Header hash mismatch (database may be corrupt)")

            print(
                f"{dbname}:$keepass$*{kdbx_version}*{transform_rounds}*"
                f"{kdf_uuid:08x}*{argon2_m}*{argon2_v}*{argon2_p}*"
                f"{master_seed.hex()}*"
                f"{transform_seed.hex()}*"
                f"{header.hex()}*"
                f"{header_hmac.hex()}"
            )


# --- Entry Point ---

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python keepass2john_py.py <database.kdbx>")
        sys.exit(1)

    process_database(sys.argv[1])