import binascii
import enum
import os
import secrets
import sys
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from secret_sharing.shamir import Shamir


class CipherMode(enum.Enum):
    AES = 1
    ChaCha20 = 2
    Camellia = 3


class CryptoSplit:

    @staticmethod
    def split_file(filein, fileout, min_shares, total_shares, key=None, mode=CipherMode.AES, sharesonly=False,
                   max_chunk=2048):
        schema_lens = CryptoSplit._get_len_elements_from_mode(mode)
        if key is None:
            key = secrets.token_bytes(32)
        iv = secrets.token_bytes(schema_lens['iv'])
        cipher = CryptoSplit._get_cipher_from_mode(mode, key, iv)
        encryptor = cipher.encryptor()
        h = hmac.HMAC(key, hashes.SHA256(), default_backend())

        shares = Shamir().create(min_shares, total_shares, key)
        shares = [(shares.index(item), item.encode('utf-8')) for item in shares]
        tmp = tempfile.NamedTemporaryFile(delete=False, prefix='cryptosplit_').name
        with open(filein, "rb") as f:
            with open(tmp, 'wb') as fo:
                b = f.read(max_chunk)
                while b:
                    ret = encryptor.update(b)
                    h.update(b)
                    fo.write(ret)
                    b = f.read(max_chunk)
                fo.write(encryptor.finalize())
        tag = h.finalize()
        written_files = 0
        if sharesonly:
            with open(fileout, 'wb') as fo:
                fo.write(iv + tag)
                with open(tmp, "rb") as f:
                    b = f.read(max_chunk)
                    while b:
                        fo.write(b)
                        b = f.read(max_chunk)
            while written_files < total_shares:
                with open(fileout + "{}_{}".format(written_files + 1, total_shares) + '.share', 'wb') as fo_share:
                    fo_share.write(int.to_bytes(mode.value, schema_lens['mode'], 'little'))
                    fo_share.write(int.to_bytes(shares[written_files][0], schema_lens['share_index'], 'little'))
                    fo_share.write(int.to_bytes(len(shares[written_files][1]), schema_lens['share_len'], 'little'))
                    fo_share.write(shares[written_files][1])
                    written_files += 1
        else:
            written_bytes_ct = 0
            len_ct = os.stat(tmp).st_size
            with open(tmp,'rb') as ftmp:
                while written_files < total_shares:
                    with open(fileout + "{}_{}".format(written_files + 1, total_shares), "wb") as fo:
                        fo.write(int.to_bytes(int(total_shares == min_shares), schema_lens['incomplete'], 'little'))
                        fo.write(int.to_bytes(mode.value, schema_lens['mode'], 'little'))
                        fo.write(int.to_bytes(shares[written_files][0], schema_lens['share_index'], 'little'))
                        fo.write(int.to_bytes(len(shares[written_files][1]), schema_lens['share_len'], 'little'))
                        fo.write(shares[written_files][1])
                        fo.write(iv + tag)
                        if total_shares == min_shares:
                            last_byte = written_bytes_ct + int(len_ct / total_shares)
                            if last_byte > len_ct:
                                last_byte = len_ct
                            elif written_files == total_shares - 1:
                                last_byte = len_ct
                            b = ftmp.read(max_chunk)
                            while b:
                                written_bytes_ct += fo.write(b)
                                if written_bytes_ct == last_byte:
                                    break
                                b = ftmp.read(max_chunk)
                        else:
                            b = ftmp.read(2048)
                            while b:
                                fo.write(b)
                                b = ftmp.read(2048)
                            ftmp.seek(0)
                        written_files += 1
            os.remove(tmp)
        return shares

    @staticmethod
    def reconstruct_file(filein, fileout, fshares=None, max_chunk=2048):
        if fshares is None:
            fshares = []
        if len(filein) == 1 and len(fshares) == 0:
            print("You can't reconstruct this file without passing the shares")
            sys.exit(1)
        elif len(filein) == 1 and len(fshares) > 0:
            shares = []
            for share in fshares:
                with open(share, 'rb') as fi:
                    mode = int.from_bytes(fi.read(8), 'little')
                    schema_lens = CryptoSplit._get_len_elements_from_mode(mode)
                    index = int.from_bytes(fi.read(schema_lens['share_index']), 'little')
                    len_key = int.from_bytes(fi.read(schema_lens['share_len']), 'little')
                    p_key = fi.read(len_key).decode("utf-8")
                    shares.append((index, p_key))
            shares = [item[1] for item in shares]
            try:
                key = Shamir().combine(shares)
            except binascii.Error:
                print("The shares were incorrect")
                sys.exit(1)
            with open(filein[0], 'rb') as fi:
                iv, tag = [fi.read(x) for x in [schema_lens['iv'], schema_lens['tag']]]
                cipher = CryptoSplit._get_cipher_from_mode(mode, key, iv)
                h = hmac.HMAC(key, hashes.SHA256(), default_backend())
                decryptor = cipher.decryptor()
                with open(fileout, 'wb') as fo:
                    b = fi.read(max_chunk)
                    while b:
                        ret = decryptor.update(b)
                        h.update(ret)
                        fo.write(ret)
                        b = fi.read(max_chunk)
                    fo.write(decryptor.finalize())
                try:
                    h.verify(tag)
                except InvalidSignature:
                    print("The shares were incorrect")
                    os.remove(fileout)
                    sys.exit(1)
        elif len(filein) > 1 and len(fshares) == 0:
            mode, iv, tag, incomplete, ordered_frags, shares, len_share = CryptoSplit._get_info_from_frags(filein)
            schema_lens = CryptoSplit._get_len_elements_from_mode(mode)
            try:
                key = Shamir().combine(shares)
            except binascii.Error:
                print("The shares were incorrect")
                sys.exit(1)
            cipher = CryptoSplit._get_cipher_from_mode(mode, key, iv)
            decryptor = cipher.decryptor()
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            source = CryptoSplit._get_complete_source(ordered_frags, incomplete, max_chunk, len_share, mode)
            with open(source, 'rb') as fi:
                with open(fileout, "wb") as fo:
                    if not incomplete:
                        [fi.read(x) for x in
                         [schema_lens['incomplete'], schema_lens['mode'], schema_lens['share_index'],
                          schema_lens['share_len'], len_share, schema_lens['iv'], schema_lens['tag']]]
                    b = fi.read(max_chunk)
                    while b:
                        ret = decryptor.update(b)
                        h.update(ret)
                        fo.write(ret)
                        b = fi.read(max_chunk)
                    fo.write(decryptor.finalize())
            try:
                if incomplete:
                    os.remove(source)
                h.verify(tag)
            except InvalidSignature:
                print("The shares were incorrect")
                os.remove(fileout)
                sys.exit(1)
        else:
            print('You cant mix input files and shares')

    @staticmethod
    def _get_info_from_frags(frags):
        nonce = None
        tag = None
        incomplete = None
        ordered_frags = []
        shares = []
        len_share = None
        mode = None
        for frag in frags:
            with open(frag, 'rb') as f:
                tmp_incomplete = bool.from_bytes(f.read(1), 'little')
                mode = int.from_bytes(f.read(8), 'little')
                schema_lens = CryptoSplit._get_len_elements_from_mode(mode)
                index = int.from_bytes(f.read(schema_lens['share_index']), 'little')
                len_share = int.from_bytes(f.read(schema_lens['share_len']), 'little')
                p_key = f.read(len_share).decode("utf-8")
                shares.append((index, p_key))
                found_nonce, found_tag = [f.read(x) for x in [schema_lens['iv'], schema_lens['tag']]]
                if nonce is None:
                    nonce = found_nonce
                elif nonce != found_nonce:
                    print('Fragments have discrepancies, aborting...')
                    sys.exit(1)
                if tag is None:
                    tag = found_tag
                elif tag != found_tag:
                    print('Fragments have discrepancies, aborting...')
                    sys.exit(1)
                if incomplete is None:
                    incomplete = tmp_incomplete
                elif incomplete != tmp_incomplete:
                    print('Fragments have have discrepancies, aborting...')
                    sys.exit(1)
                ordered_frags.append((index, frag))
                f.close()
        ordered_frags.sort(key=lambda tup: tup[0])
        ordered_frags = [item[1] for item in ordered_frags]
        shares = [item[1] for item in shares]
        return mode, nonce, tag, incomplete, ordered_frags, shares, len_share

    @staticmethod
    def _get_complete_source(ordered_frags, incomplete, max_chunk, len_share, mode):
        source = ordered_frags[0]
        schema_lens = CryptoSplit._get_len_elements_from_mode(mode)
        if incomplete:
            source = tempfile.NamedTemporaryFile(delete=False, prefix='cryptosplit_').name
            with open(source, "wb") as fo:
                for frag in ordered_frags:
                    with open(frag, 'rb') as fi:
                        [fi.read(x) for x in
                         [schema_lens['incomplete'], schema_lens['mode'], schema_lens['share_index'],
                          schema_lens['share_len'], len_share, schema_lens['iv'], schema_lens['tag']]]
                        b = fi.read(max_chunk)
                        while b:
                            fo.write(b)
                            b = fi.read(max_chunk)
        return source

    @staticmethod
    def _get_cipher_from_mode(mode, key, iv):
        if isinstance(mode, int):
            mode = CipherMode(mode)
        if mode == CipherMode.AES:
            return Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        elif mode == CipherMode.ChaCha20:
            return Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
        elif mode == CipherMode.Camellia:
            return Cipher(algorithms.Camellia(key), modes.CTR(iv), backend=default_backend())
        else:
            return None

    @staticmethod
    def _get_len_elements_from_mode(mode):
        if isinstance(mode, int):
            mode = CipherMode(mode)
        if mode == CipherMode.AES:
            return {'incomplete': 1, 'mode': 8, 'share_index': 8, 'share_len': 8, 'iv': 16, 'tag': 32}
        elif mode == CipherMode.ChaCha20:
            return {'incomplete': 1, 'mode': 8, 'share_index': 8, 'share_len': 8, 'iv': 16, 'tag': 32}
        elif mode == CipherMode.Camellia:
            return {'incomplete': 1, 'mode': 8, 'share_index': 8, 'share_len': 8, 'iv': 16, 'tag': 32}
        else:
            return None
