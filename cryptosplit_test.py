import hashlib
import os
import unittest
from os.path import isfile, join

from crypto_split import CryptoSplit, CipherMode


class TestCryptoSplit(unittest.TestCase):

    def test_split_reconstruct_AES(self):
        hash_original = _get_sha256_file('setup.py')
        CryptoSplit.split_file('setup.py', 'unittest', 3, 5, mode=CipherMode.AES)
        CryptoSplit.reconstruct_file(['unittest1_5', 'unittest3_5', 'unittest5_5'], 'unittest_rec')
        self.assertEqual(hash_original, _get_sha256_file('unittest_rec'))
        _cleanup()

    def test_split_reconstruct_AES_frag(self):
        hash_original = _get_sha256_file('setup.py')
        CryptoSplit.split_file('setup.py', 'unittest', 5, 5, mode=CipherMode.AES)
        CryptoSplit.reconstruct_file(['unittest3_5', 'unittest1_5',  'unittest2_5', 'unittest4_5',  'unittest5_5'], 'unittest_rec')
        self.assertEqual(hash_original, _get_sha256_file('unittest_rec'))
        _cleanup()

    def test_split_reconstruct_AES_shares_only(self):
        hash_original = _get_sha256_file('setup.py')
        CryptoSplit.split_file('setup.py', 'unittest', 3, 5, mode=CipherMode.AES, sharesonly=True)
        CryptoSplit.reconstruct_file(['unittest'],'unittest_rec', fshares=['unittest1_5.shares', 'unittest3_5.shares', 'unittest5_5.shares'])
        self.assertEqual(hash_original, _get_sha256_file('unittest_rec'))
        _cleanup()

    def test_split_reconstruct_ChaCha20(self):
        hash_original = _get_sha256_file('setup.py')
        CryptoSplit.split_file('setup.py', 'unittest', 3, 5, mode=CipherMode.ChaCha20)
        CryptoSplit.reconstruct_file(['unittest1_5', 'unittest3_5', 'unittest5_5'], 'unittest_rec')
        self.assertEqual(hash_original, _get_sha256_file('unittest_rec'))
        _cleanup()

    def test_split_reconstruct_ChaCha20_frag(self):
        hash_original = _get_sha256_file('setup.py')
        CryptoSplit.split_file('setup.py', 'unittest', 5, 5, mode=CipherMode.ChaCha20)
        CryptoSplit.reconstruct_file(['unittest3_5', 'unittest1_5',  'unittest2_5', 'unittest4_5',  'unittest5_5'], 'unittest_rec')
        self.assertEqual(hash_original, _get_sha256_file('unittest_rec'))
        _cleanup()

    def test_split_reconstruct_ChaCha20_shares_only(self):
        hash_original = _get_sha256_file('setup.py')
        CryptoSplit.split_file('setup.py', 'unittest', 3, 5, mode=CipherMode.ChaCha20, sharesonly=True)
        CryptoSplit.reconstruct_file(['unittest'],'unittest_rec', fshares=['unittest1_5.shares', 'unittest3_5.shares', 'unittest5_5.shares'])
        self.assertEqual(hash_original, _get_sha256_file('unittest_rec'))
        _cleanup()

    def test_split_reconstruct_Camellia(self):
        hash_original = _get_sha256_file('setup.py')
        CryptoSplit.split_file('setup.py', 'unittest', 3, 5, mode=CipherMode.Camellia)
        CryptoSplit.reconstruct_file(['unittest1_5', 'unittest3_5', 'unittest5_5'], 'unittest_rec')
        self.assertEqual(hash_original, _get_sha256_file('unittest_rec'))
        _cleanup()

    def test_split_reconstruct_Camellia_frag(self):
        hash_original = _get_sha256_file('setup.py')
        CryptoSplit.split_file('setup.py', 'unittest', 5, 5, mode=CipherMode.Camellia)
        CryptoSplit.reconstruct_file(['unittest3_5', 'unittest1_5',  'unittest2_5', 'unittest4_5',  'unittest5_5'], 'unittest_rec')
        self.assertEqual(hash_original, _get_sha256_file('unittest_rec'))
        _cleanup()

    def test_split_reconstruct_Camellia_shares_only(self):
        hash_original = _get_sha256_file('setup.py')
        CryptoSplit.split_file('setup.py', 'unittest', 3, 5, mode=CipherMode.Camellia, sharesonly=True)
        CryptoSplit.reconstruct_file(['unittest'],'unittest_rec', fshares=['unittest1_5.shares', 'unittest3_5.shares', 'unittest5_5.shares'])
        self.assertEqual(hash_original, _get_sha256_file('unittest_rec'))
        _cleanup()

def _get_sha256_file(file):
    with open(file, "rb") as f:
        bytes = f.read()  # read entire file as bytes
        readable_hash = hashlib.sha256(bytes).hexdigest()
        return readable_hash


def _cleanup():
    pdir = os.path.dirname(os.path.abspath(__file__))
    files = [f for f in os.listdir(pdir) if isfile(join(pdir, f)) and f.startswith('unittest')]
    for f in files:
        os.remove(f)


if __name__ == '__main__':
    unittest.main()
