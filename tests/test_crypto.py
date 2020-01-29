import getpass
from unittest import mock

import pytest

from .test_file import FileKeyringTests

from keyrings.alt import file


def is_crypto_supported():
    try:
        __import__('Crypto.Cipher.AES')
        __import__('Crypto.Protocol.KDF')
        __import__('Crypto.Random')
    except ImportError:
        return False
    return True


@pytest.mark.skipif(not is_crypto_supported(), reason="Need Crypto module")
class TestCryptedFileKeyring(FileKeyringTests):
    @pytest.fixture(autouse=True)
    def mocked_getpass(self, monkeypatch):
        fake_getpass = mock.Mock(return_value='abcdef')
        monkeypatch.setattr(getpass, 'getpass', fake_getpass)

    def init_keyring(self):
        return file.EncryptedKeyring()
