#!/usr/bin/env python3
import argparse
import sys
from os.path import abspath

from crypto_split.cryptosplit import CryptoSplit, CipherMode


def main():
    if len(sys.argv) < 2 or (sys.argv[1] != 'split' and sys.argv[1] != 'bind'):
        usage()
        sys.exit(1)
    mode = sys.argv[1]
    sys.argv.remove(mode)
    parser = getparser(mode)
    args = parser.parse_args()
    if len(sys.argv) < 6:
        parser.print_help()
        sys.exit(1)
    if mode == 'split':
        fi = abspath(args.i)
        fo = abspath(args.o)
        m = int(args.m)
        t = int(args.t)
        if m > t:
            print("Minimum number of fragments can't be greater than the total")
            sys.exit(1)
        elif m == 1:
            print('There is no point in using m=1. Please use m>2')
            sys.exit(1)
        if args.cipher is None or len(args.cipher) == 0:
            mode = get_cipher_mode('AES')
        elif len(args.cipher) == 1:
            mode = get_cipher_mode(args.cipher[0])
        elif len(args.cipher) > 1:
            print('You can choose only one cipher')
            sys.exit(1)
        CryptoSplit.split_file(fi, fo, m, t, mode=mode, sharesonly=args.sharesonly)
    elif mode == 'bind':
        fi = [abspath(item) for item in args.i]
        fs = [abspath(item) for item in args.s]
        fo = abspath(args.o)
        CryptoSplit.reconstruct_file(fi, fo, fshares=fs)


def getparser(mode):
    parser = argparse.ArgumentParser(prog="cryptosplit " + mode)
    if mode == 'split':
        parser.add_argument('-i', help='Original file relative path')
        parser.add_argument('-o', help='Relative path of the output files')
        parser.add_argument('-t', help='Total number of fragments')
        parser.add_argument('-m', help='Minimum number of fragments required for reconstruction')
        parser.add_argument('-so', '--sharesonly', action='store_true',
                            help='Make output files only contain the share required for decryption')
        parser.add_argument('-c', '--cipher', help="Chosen cipher[AES|ChaCha20|Camellia] (default: AES)",
                            nargs='*')
    else:
        parser.add_argument('-i', nargs='+', help='Encrypted files relative paths')
        parser.add_argument('-o', help='Desired file name/path of the output')
        parser.add_argument('-s', nargs='+',
                            help='Share files relative paths (required only if encrypted with option --sharesonly)', default=[])


    return parser


def get_cipher_mode(name):
    name = name.lower()
    if name == 'aes':
        return CipherMode.AES
    elif name == 'chacha20' or name == 'chacha':
        return CipherMode.ChaCha20
    elif name == 'camellia':
        return CipherMode.Camellia


def usage():
    print("Usage:")
    print("  cryptosplit [split|bind]")
    print("")
    print("Options:")
    print("  split                      Encrypt a file")
    print("  bind                      Decrypt a file")
    print("")
    sys.exit(1)
