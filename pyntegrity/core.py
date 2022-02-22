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
import re

from .exceptions import HashStrNotValidException
from .exceptions import HashAlgorithmNotSupportedException

from .config import SUPPORTED_HASH_ALGOS


def detect_hash_algo(hash_str: str):
    """
    Detects hash algorithm based on its length.

    :param hash_str: the hash string
    :return: the name of the hash algorithm
    :raises HashAlgorithmNotSupportedException: raised if the hash
        length isn't valid for any supported algorithm
    """
    hash_len = len(hash_str)
    for name, infos in SUPPORTED_HASH_ALGOS.items():
        if infos["LENGTH"] == hash_len:
            return name
    else:
        raise HashAlgorithmNotSupportedException(
            detected_length=hash_len, hash_str=hash_str
        )


def validate_hash_str(hash_str: str):
    """
    Checks if the str is a valid checksum in the detected algorithm

    :param hash_str:the hash string
    :return: True if valid
    :raises HashStrNotValidException: raised if the hash str isn't valid
    """
    hash_name = detect_hash_algo(hash_str)
    pattern = re.compile(SUPPORTED_HASH_ALGOS[hash_name]["REX"])
    if pattern.match(hash_str):
        return True
    else:
        raise HashStrNotValidException(detected_hash_algo=hash_name, hash_str=hash_str)
