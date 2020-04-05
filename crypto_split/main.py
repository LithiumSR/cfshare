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
        fi = abspath(args.fi)
        fo = abspath(args.fo)
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
        fi = [abspath(item) for item in args.fi]
        fs = [abspath(item) for item in args.fs]
        fo = abspath(args.fo)
        CryptoSplit.reconstruct_file(fi, fo, fshares=fs)


def getparser(mode):
    parser = argparse.ArgumentParser(prog="cryptosplit " + mode)
    if mode == 'split':
        parser.add_argument('-fi', help='File name/path of the original file')
        parser.add_argument('-fo', help='File name of the output files')
        parser.add_argument('-t', help='Number of fragments')
        parser.add_argument('-m', help='Minimum number of fragments required for reconstruction')
        parser.add_argument('-s', '--sharesonly', action='store_true',
                            help='Make output files only contain a fragment of the key required for decryption')
        parser.add_argument('-c', '--cipher', help="Chosen cipher[AES|ChaCha20|Camellia] (default: AES)",
                            nargs='*')
    else:
        parser.add_argument('-fi', nargs='+', help='Encrypted files name')
        parser.add_argument('-fs', nargs='+',
                            help='Share files name (required only if encrypted with option -sharesonly)', default=[])
        parser.add_argument('-fo', help='File name of the output files')

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
