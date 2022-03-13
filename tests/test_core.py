from pathlib import Path
from unittest import TestCase

from pyntegrity.core import detect_hash_algo
from pyntegrity.core import IntegrityValidator
from pyntegrity.core import validate_checksum_str
from pyntegrity.core import get_file_path_from_str

from pyntegrity.exceptions import FileNotFoundException
from pyntegrity.exceptions import ObjectNotAFileException
from pyntegrity.exceptions import HashStrNotValidException
from pyntegrity.exceptions import HashAlgorithmNotSupportedException


class TestDetectHashAlgo(TestCase):
    def test_detect_hash_algo_ok(self):
        str32_len = "098f6bcd4621d373cade4e832627b4f6"
        str64_len = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        hash_name = detect_hash_algo(str32_len)
        self.assertEqual(hash_name, "md5")
        hash_name = detect_hash_algo(str64_len)
        self.assertEqual(hash_name, "sha256")

    def test_detect_hash_algo_nok(self):
        invalid_checksum_str = "6545ed"
        with self.assertRaises(HashAlgorithmNotSupportedException):
            detect_hash_algo(invalid_checksum_str)


class TestValidateHashStr(TestCase):
    def test_validate_checksum_str_md5_ok(self):
        valid_md5 = "098f6bcd4621d373cade4e832627b4f6"
        self.assertTrue(validate_checksum_str(valid_md5, "md5"))

    def test_validate_checksum_str_md5_nok(self):
        invalid_md5 = "098f6bcd4621d373xade4e832627b4f6"
        with self.assertRaises(HashStrNotValidException):
            validate_checksum_str(invalid_md5, "md5")

    def test_validate_checksum_str_sha256_ok(self):
        valid_sha256 = (
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        )
        self.assertTrue(validate_checksum_str(valid_sha256, "sha256"))

    def test_validate_checksum_str_sha256_nok(self):
        invalid_sha256 = (
            "9f86d081884x7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        )
        with self.assertRaises(HashStrNotValidException):
            validate_checksum_str(invalid_sha256, "sha256")


class TestGetFileFromStr(TestCase):
    def test_get_file_path_from_str_ok(self):
        obj = get_file_path_from_str("tests/data/test_file.txt")
        self.assertTrue(isinstance(obj, Path))

    def test_get_file_path_from_str_nok_is_not_file(self):
        with self.assertRaises(ObjectNotAFileException):
            get_file_path_from_str("tests/data/")

    def test_get_file_path_from_str_nok_not_found(self):
        with self.assertRaises(FileNotFoundException):
            get_file_path_from_str("tests/data/doesnt_exists.csv")


class TestGetFileChecksum(TestCase):
    def test_get_file_checksum_text(self):
        obj = IntegrityValidator(
            str_path="tests/data/test_file.txt",
            checksum_str="bbe4f28b27120e0a9611d90d242bc656",
        )
        self.assertEqual(
            obj.get_file_checksum("md5"),
            "bbe4f28b27120e0a9611d90d242bc656",
        )

    def test_get_file_checksum_bin(self):
        obj = IntegrityValidator(
            str_path="tests/data/test_file.dat",
            checksum_str="0cb988d042a7f28dd5fe2b55b3f5ac7a",
        )
        self.assertEqual(
            obj.get_file_checksum("md5"),
            "0cb988d042a7f28dd5fe2b55b3f5ac7a",
        )


class TestValidateFileIntegrity(TestCase):
    def test_validate_file_integrity_true(self):
        obj = IntegrityValidator(
            str_path="tests/data/test_file.dat",
            checksum_str="0cb988d042a7f28dd5fe2b55b3f5ac7a",
        )
        self.assertTrue(obj.validate_file_integrity())

    def test_validate_file_integrity_false(self):
        obj = IntegrityValidator(
            str_path="tests/data/test_file.dat",
            checksum_str="0cb988d042a7f28dd5fe2b55b3fbac7a",
        )
        self.assertFalse(obj.validate_file_integrity())
