import hashlib
import sys

MB = 1024 * 1024
MAX_READ = 32 * MB
SMDH = -1

def bytes2int(data: bytes) -> int:
    return int.from_bytes(data, byteorder='little')

def patchByte(buf: bytearray, offset: int, data: bytes):
    buf[offset:offset + len(data)] = data

def updateSHA256(buf: bytearray, hash_offset, data_offset, length):
    segment = buf[data_offset:data_offset + length]
    sha = hashlib.sha256(segment).digest()
    patchByte(buf, hash_offset, sha)

def findSMDH(buf: bytearray):
    global exefs
    global smdh

    exefs = bytes2int(buf[0x1A0:0x1A4]) * 0x200
    smdh_offset = bytes2int(buf[exefs + 0x28:exefs + 0x2C]) + 0x200

    magic = buf[exefs + smdh_offset:exefs + smdh_offset + 4]
    if magic != b'SMDH':
        return -1

    return exefs + smdh_offset

# --- Main ---
if len(sys.argv) < 2:
    print

