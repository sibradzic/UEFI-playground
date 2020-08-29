#!/usr/bin/env python3

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

#
# For latest version check https://github.com/sibradzic/UEFI-playground
#

import argparse
import binascii
import ctypes
import hashlib
import os
import stat
import sys
import urllib.request
from shutil import rmtree
from zipfile import ZipFile

VENDOR_UUID = '389CC6F2-1EA8-467B-AB8A-78E769AE2A15'
GITHUB_PREFIX = 'https://github.com/LongSoft/UEFITool/releases/download/'
binaries = {
    'UEFIExtract': {
        'rel': 'NE_A57',
        'md5':  '7907c0416206183dc6e94944c05c07bb'
    },
    'UEFIReplace': {
        'rel': '0.28.0',
        'md5':  'a816ee512d76d5556761fc8749a29267'
    }
}

# Determine system platform
bin_suffix = ''
if sys.platform == 'linux':
    platform = 'linux_x86_64'
elif sys.platform == 'win32':
    platform = sys.platform
    bin_suffix = '.exe'
elif sys.platform == 'darwin':
    platform = 'mac'
else:
    print('Unsupported platform', sys.platform)
    sys.exit(2)


# Helper that returns a hash of a binary file
def file_hash(binfile, algo):
    hashfunc = getattr(hashlib, algo)
    h = hashfunc()
    with open(binfile, 'rb') as file:
        file = open(binfile, 'rb')
        while True:
            chunk = file.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest()


# Helper for fetching UEFITools binaries
def get_binary(name, release, md5):
    full_url = GITHUB_PREFIX + release.lstrip('NE_') + '/' + name + '_' + \
               release + '_' + platform + '.zip'
    print('Downloading', full_url)
    urllib.request.urlretrieve(full_url, name + '.zip')
    print('Extracting', name + '.zip ...')
    zip = ZipFile(name + '.zip')
    zip.extractall()
    zip.close()
    os.remove(name + '.zip')
    os.chmod(name + bin_suffix, stat.S_IRWXU)
    # TODO: md5 checks on win32 & darwin platforms
    if platform == 'linux' and file_hash(name, 'md5') != md5:
        print(name, 'md5 sum does not match', md5)
        sys.exit(2)


parser = argparse.ArgumentParser(description='UEFI Vendor hash fixer')
parser.add_argument('inputrom', help='Input ROM file')
parser.add_argument('--debug', help='Print debug info', action='store_true')
args = parser.parse_args()

# Get UEFITool binaries (unless they are already present in the working dir)
for binary in binaries:
    if not os.path.exists(binary + bin_suffix):
        get_binary(binary, binaries[binary]['rel'], binaries[binary]['md5'])

# Generate report on internal structure of the input ROM file
print('Generating structure report of', args.inputrom)
os.system('./UEFIExtract ' + args.inputrom + ' report')

print('Calculating sha256 hashes of FFS volumes ...')
ffsv2_vols = {}
hash_tables = {}
UEFI_base_addr = 0
with open(args.inputrom + '.report.txt') as report:
    for line in report:
        entries = line.strip().split('|')
        if 'BIOS region' in line:
            BIOS_region_base_hex_str = entries[2].strip().lstrip('0')
            UEFI_base_addr = int(BIOS_region_base_hex_str, 16)
            if args.debug:
                print(('DEBUG: UEFI BIOS region base address: '
                       '{:X}').format(UEFI_base_addr, UEFI_base_addr))
                print('DEBUG: FFS volumes:')
        if ('FFSv' in line or VENDOR_UUID in line) and 'N/A' not in line:
            baseaddr = int(entries[2].strip().lstrip('0'), 16)
            real_offset = baseaddr - UEFI_base_addr
            baseaddr_hex_str = '{:X}'.format(real_offset)
            size = int(entries[3].strip().lstrip('0'), 16)
            vol_uuid = entries[5].split('- ')[-1]
            with open(args.inputrom, 'rb') as uefi_image:
                uefi_image.seek(baseaddr, 0)
                module_data = uefi_image.read(size)
            if 'FFSv' in line:
                ffsv2sha256 = hashlib.sha256(module_data)
                ffsv2_vols[baseaddr_hex_str] = ffsv2sha256.hexdigest()
                if args.debug:
                    print(('DEBUG: @ {:7X}h sha256: '
                           '{}').format(real_offset,
                                        ffsv2_vols[baseaddr_hex_str]))
            if VENDOR_UUID in line:
                if args.debug:
                    print(('DEBUG: @ {:7X}h {} bytes long vendor hash table'
                           '').format(real_offset, size))
                hash_tables[baseaddr_hex_str] = {
                  'header': module_data[:24],
                  'body': module_data[24:],
                  'size': len(module_data)
                }
                last_htable_addr = baseaddr_hex_str

# Check if all hash tables are identical copies
for base_addr in hash_tables:
    if not hash_tables[base_addr] == hash_tables[last_htable_addr]:
        print(('ERROR: Vendor hash table @ {} differs from one @ {}, which is'
               'not something UEFIReplace can fix. Bailing out.'
               '').format(base_addr, last_htable_addr))
        sys.exit(2)

hash_header_bytes = hash_tables[last_htable_addr]['header']
hash_body_bytes = hash_tables[last_htable_addr]['body']
hash_tbl_size = hash_tables[base_addr]['size']


# Classes defining C structure data in vendor hash table
class hash_header(ctypes.Structure):
    _fields_ = [
        ("signature", ctypes.c_char * 8),
        ("length",    ctypes.c_uint32)
    ]


headerbytes = bytearray(hash_body_bytes[:12])
header = hash_header.from_buffer(headerbytes)


class hash_record(ctypes.Structure):
    _fields_ = [
        ("hash",   ctypes.c_byte * 32),
        ("offset", ctypes.c_uint32),
        ("size",   ctypes.c_uint32)
    ]


class hash_struct(ctypes.Structure):
    _fields_ = [
        ("header",  hash_header),
        ("records", hash_record * header.length)
    ]


rwbytes = bytearray(hash_body_bytes)
hashes = hash_struct.from_buffer(rwbytes)

if hashes.header.signature == b'$HASHTBL':
    print(('Found vendor hash table with {} '
           'entries:').format(hashes.header.length))

fix_needed = False
for record in hashes.records:
    vendor_hash = str(binascii.hexlify(record.hash), 'utf-8')
    offset, size = record.offset, record.size
    hex_base = '{:X}'.format(offset)
    hex_size = '{:X}'.format(size)
    if args.debug:
        print('DEBUG: Vendor sha256 entry:', hex_base, hex_size, vendor_hash)
    if hex_base in ffsv2_vols:
        real_hash = ffsv2_vols[hex_base]
        if real_hash == vendor_hash:
            print('FFS volume @ {}h hash256 OK'.format(hex_base))
        else:
            print(('FFS volume @ {}h hash256 mismatch! Overriding from '
                   '{} to {}').format(hex_base, vendor_hash, real_hash))
            hash_buff = bytearray(binascii.unhexlify(real_hash))
            record.hash = (ctypes.c_byte * 32).from_buffer(hash_buff)
            fix_needed = True

if fix_needed:
    with open('vendor_modified.bin', 'wb') as target:
        target.write(hash_header_bytes)
        target.write(hashes)
        padding = hash_tbl_size - len(hash_header_bytes + hashes)
        if padding:
            print(('WARNING: Adding {} zero padding bytes to the hash table to'
                  ' preserve the original table size').format(padding))
            target.write(bytes(padding))
    print('Replacing vendor hash module')
    os.system('./UEFIReplace ' + args.inputrom + ' ' + VENDOR_UUID +
              ' 01 vendor_modified.bin -all -asis')
    print('Fixed ROM image written as', args.inputrom + '.patched')

# Cleanup
try:
    os.remove(args.inputrom + '.report.txt')
    os.remove('vendor_modified.bin')
except OSError:
    pass
