from unittest import TestCase

from pyntegrity.core import detect_hash_algo
from pyntegrity.core import validate_hash_str

from pyntegrity.exceptions import HashStrNotValidException
from pyntegrity.exceptions import HashAlgorithmNotSupportedException


class TestDetectHashAlgo(TestCase):
    def test_detect_hash_algo_ok(self):
        str32_len = "xzazyokqvhqzjbeyxpldfntsjiaumxan"
        str64_len = "cmolcmtdtxffmfqnjgadqteqnnmacnhysxwpdanwtqzibkysmawoqxdiippzxpum"
        hash_name = detect_hash_algo(str32_len)
        self.assertEqual(hash_name, "md5")
        hash_name = detect_hash_algo(str64_len)
        self.assertEqual(hash_name, "sha256")

    def test_detect_hash_algo_nok(self):
        invalid_hash_str = "6545ed"
        with self.assertRaises(HashAlgorithmNotSupportedException):
            detect_hash_algo(invalid_hash_str)


class TestValidateHashStr(TestCase):
    def test_validate_hash_str_md5_ok(self):
        valid_md5 = "098f6bcd4621d373cade4e832627b4f6"
        self.assertTrue(validate_hash_str(valid_md5))

    def test_validate_hash_str_md5_nok(self):
        invalid_md5 = "098f6bcd4621d373xade4e832627b4f6"
        with self.assertRaises(HashStrNotValidException):
            validate_hash_str(invalid_md5)

    def test_validate_hash_str_sha256_ok(self):
        valid_sha256 = (
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        )
        self.assertTrue(validate_hash_str(valid_sha256))

    def test_validate_hash_str_sha256_nok(self):
        invalid_sha256 = (
            "9f86d081884x7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        )
        with self.assertRaises(HashStrNotValidException):
            validate_hash_str(invalid_sha256)
