# UEFI-playground
UEFI scripts and tools

## fix_vendor_hashes.py

This script checks and fixes the "Vendor Hash File" found on recent Lenovo
ThinkPad UEFI ROMs. Vendor Hash File is special UEFI data module consisting
a table of sha256 hashes of some of the FFSv2 UEFI volumes found within the
same UEFI ROM image.

Early in the UEFI boot process the actual sha256 hashes of FFSv2 volumes are
being compared with values in the Vendor Hash File, and in case some manual
changes in actual volumes the hashes will mismatch, resulting in boot failure
(on a particular ThinkPad that I've seen this problem, turning the machine on
results in black screen and a weird 'error code' melody being played).

This script uses UEFITools binaries to do the heavy lifting of extracting and
FFSv2 and replacing Vendor Hash File modules. It will download UEFIExtract
and UEFIReplace binaries unless they are already in the working directory.

Tested on ThinkPad A285.
