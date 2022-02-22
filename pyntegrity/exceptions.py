"""
Pyntegrity is Python package that helps checking a file integrity.
Copyright (C) 2022  Salah OSFOR

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
from .config import SUPPORTED_HASH_ALGOS


class HashAlgorithmNotSupportedException(Exception):
    def __init__(self, detected_length: int, hash_str: str):
        """
        Exception raised when the hash length does not match
        any supported Hash algorithm;

        :param detected_length: the length of the checked hash string
        :param hash_str: the hash string
        """
        self.detected_length = detected_length
        self.hash_str = hash_str
        self.message = (
            "[!] The hash string length does not "
            "match any supported hash algorithm: ["
        )
        for hash_name, infos in SUPPORTED_HASH_ALGOS.items():
            length = infos["LENGTH"]
            self.message += f" {hash_name}: {length} chars, "
        self.message += "]"

        super().__init__(self.message)


class HashStrNotValidException(Exception):
    def __init__(self, detected_hash_algo: str, hash_str: str):
        """
        Exception raised when hash string isn't valid
        for the detected hash algorithm;

        :param detected_hash_algo: the name of the detected algo
        :param hash_str: the hash string
        """
        self.detected_hash_algo = detected_hash_algo
        self.hash_str = hash_str
        self.message = (
            f"[!] The hash string doesn't "
            f'seem valid for the detected algorithm"{detected_hash_algo}"'
        )
        super().__init__(self.message)
