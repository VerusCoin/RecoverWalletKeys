## bitwalletrecover.py - recover private keys from your darkcoin wallet
## (this version was not tested with bitcoin/litecoin).
## Requires python3, pycoin (https://pypi.python.org/pypi/pycoin),
## and base58 (https://pypi.python.org/pypi/base58).
##
## Starting with Python 3.4, pip is included by default with the Python binary
## installers. To install pip for older versions 3.x:
##
##   sudo apt-get install python3-setuptools
##   sudo easy_install3 pip
##
## Install libs:
##
##   sudo pip install pycoin
##   sudo pip install base58
##
## Donations are welcome :)
## DRK: XsV4GHVKGTjQFvwB7c6mYsGV3Mxf7iser6

import re
import hashlib
import base58
from pycoin.ecdsa import generator_secp256k1, public_pair_for_secret_exponent

def from_long(v, prefix, base, charset):
    """The inverse of to_long. Convert an integer to an arbitrary base.
    v: the integer value to convert
    prefix: the number of prefixed 0s to include
    base: the new base
    charset: an array indicating what printable character to use for each value.
    """
    l = bytearray()
    while v > 0:
        try:
            v, mod = divmod(v, base)
            l.append(charset(mod))
        except Exception:
            raise EncodingError("can't convert to character corresponding to %d" % mod)
    l.extend([charset(0)] * prefix)
    l.reverse()
    return bytes(l)

def to_bytes_32(v):
    v = from_long(v, 0, 256, lambda x: x)
    if len(v) > 32:
        raise ValueError("input to to_bytes_32 is too large")
    return ((b'\0' * 32) + v)[-32:]

def bytetohex(byteStr):
    return ''.join( [ "%02X" % x for x in byteStr ] ).strip()

litecoin = [b"\x30", b"\xb0"]
bitcoin = [b"\x00", b"\x80"]
darkcoin = [b"\x4c", b"\xcc"]
verus = [b"\x3c", b"\xbc"]

cointype = verus

walletHandle = open("wallet.dat", "rb")
wallet = walletHandle.read()

privKeys_re_c=re.compile(b'\x30\x81\xD3\x02\x01\x01\x04\x20(.{32})', re.DOTALL)
privKeys=set(privKeys_re_c.findall(wallet))

print("#Found %d privKeys" % len(privKeys))

for key in privKeys:

    public_x, public_y = public_pair_for_secret_exponent(generator_secp256k1, int(bytetohex(key), 16))

    public_key = b'\4' + to_bytes_32(public_x) + to_bytes_32(public_y)
    compressed_public_key = bytes.fromhex("%02x%064x" % (2 + (public_y & 1), public_x))

    ## https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses

    m = hashlib.new('ripemd160')
    m.update(hashlib.sha256(public_key).digest())
    ripe = m.digest() # Step 2 & 3

    m = hashlib.new('ripemd160')
    m.update(hashlib.sha256(compressed_public_key).digest())
    ripe_c = m.digest() # Step 2 & 3

    extRipe = cointype[0] + ripe # Step 4
    extRipe_c = cointype[0] + ripe_c # Step 4


    chksum = hashlib.sha256(hashlib.sha256(extRipe).digest()).digest()[:4] # Step 5-7
    chksum_c = hashlib.sha256(hashlib.sha256(extRipe_c).digest()).digest()[:4] # Step 5-7

    addr = extRipe + chksum # Step 8
    addr_c = extRipe_c + chksum_c # Step 8

    #print("Public Key (130 characters [0-9A-F]):", bytetohex(public_key))
    #print("Public Key (compressed, 66 characters [0-9A-F]):", bytetohex(compressed_public_key))
    #print("Public Address:", base58.b58encode(addr))
    #print("Public Address Compressed:", base58.b58encode(addr_c))

    ## WIF https://en.bitcoin.it/wiki/Wallet_import_format
    ## compressed WIF http://sourceforge.net/mailarchive/forum.php?thread_name=CAPg%2BsBhDFCjAn1tRRQhaudtqwsh4vcVbxzm%2BAA2OuFxN71fwUA%40mail.gmail.com&forum_name=bitcoin-development

    keyWIF = cointype[1] + key
    keyWIF_c = cointype[1] + key + b"\x01"
    
    chksum = hashlib.sha256(hashlib.sha256(keyWIF).digest()).digest()[:4]
    chksum_c = hashlib.sha256(hashlib.sha256(keyWIF_c).digest()).digest()[:4]

    addr = keyWIF + chksum # Step 8
    addr_c = keyWIF_c + chksum_c # Step 8
    #print("Private Key Hexadecimal Format (64 characters [0-9A-F]):", bytetohex(key))
    #print("Private Key WIF (51 Base58 characters):", base58.b58encode(addr))
    #print("Private Key WIF Compressed (52 Base58 characters):", base58.b58encode(addr_c),"\n")
    print("fiat/verus importprivkey", base58.b58encode(addr_c).decode("utf-8"), '"" false')

walletHandle.close()
