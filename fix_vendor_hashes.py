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
ffs_vols = {}
hash_tables = {}
with open(args.inputrom + '.report.txt') as report:
    if args.debug:
        print('DEBUG: FFS volumes reported by UEFIExtract:')
    for line in report:
        entries = line.strip().split('|')
        if ('FFSv' in line or VENDOR_UUID in line) and 'N/A' not in line:
            baseaddr = int(entries[2].strip().lstrip('0'), 16)
            baseaddr_hex_str = '{:X}'.format(baseaddr)
            size = int(entries[3].strip().lstrip('0'), 16)
            vol_uuid = entries[5].split('- ')[-1]
            with open(args.inputrom, 'rb') as uefi_image:
                uefi_image.seek(baseaddr, 0)
                module_data = uefi_image.read(size)
            if 'FFSv' in line:
                ffssha256 = hashlib.sha256(module_data)
                ffs_vols[baseaddr_hex_str] = ffssha256.hexdigest()
                if args.debug:
                    print(('DEBUG: @ {:7X}h sha256: '
                           '{}').format(baseaddr, ffs_vols[baseaddr_hex_str]))
            if VENDOR_UUID in line:
                if args.debug:
                    print(('DEBUG: @ {:7X}h {} bytes long vendor hash table'
                           '').format(baseaddr, size))
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
    print(('Vendor hash table with {} '
           'entries:').format(hashes.header.length))

# On complex Intel ROM images we need to guess the correct volume offset, which
# is done by checking offset differences of volumes that match venodr sha256.
vols_offset = 0
for record in hashes.records:
    vendor_hash = str(binascii.hexlify(record.hash), 'utf-8')
    vendor_baseaddr = record.offset
    if args.debug:
        print(('DEBUG: Looking for matching sha256 entry pointing to {:X}h'
               '').format(vendor_baseaddr))
    match_vol_base = ''
    match_vols = [vol for vol in ffs_vols if ffs_vols[vol] == vendor_hash]
    if match_vols:
        # Some UEFI images (X1Eg2) have duplicated FFS volumes, so we only
        # consider the last matching volume for our check
        match_vol_base = int(match_vols[-1], 16)
        new_offset_guess = match_vol_base - vendor_baseaddr
        if args.debug and new_offset_guess:
            print(('DEBUG: Found matching volume @ {:X}h (additional offset: '
                   '{:X}h bytes)').format(match_vol_base, new_offset_guess))
        if vols_offset:
            if vols_offset != new_offset_guess:
                print('ERROR: Volume offset differs from a previous guess. '
                      'Bailing out!')
                sys.exit(2)
        vols_offset = new_offset_guess
if args.debug:
    print(('DEBUG: Assuming additional FFS volume offset of {:X}h bytes'
           '').format(vols_offset))

fix_needed = False
for record in hashes.records:
    vendor_hash = str(binascii.hexlify(record.hash), 'utf-8')
    offset, size = record.offset, record.size
    real_offset = vols_offset + offset
    hex_base = '{:X}'.format(real_offset)
    entry_str = '{:7X} (real offset: {:7X}h)'.format(offset, real_offset)
    if args.debug:
        print(('DEBUG: Checking vendor entry pointing @ {}, sha256: {}'
               '').format(entry_str, vendor_hash))
    if hex_base in ffs_vols:
        real_hash = ffs_vols[hex_base]
        if real_hash == vendor_hash:
            print(' FFS volume @ {} hash256 OK'.format(entry_str))
        else:
            print((' FFS volume @ {} hash256 mismatch! Overriding...'
                   '').format(entry_str))
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
