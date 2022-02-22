from unittest import TestCase
from pyntegrity.core import detect_hash_algo
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
