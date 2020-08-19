# Python Scale Codec
#
# Copyright 2018-2020 openAware BV (NL).
# This file is part of Polkascan.
#
# Polkascan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Polkascan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Polkascan. If not, see <http://www.gnu.org/licenses/>.
#
#  math.py

"""Some simple math-related utility functions not present in the standard
   library.
"""

from math import ceil, log2

def trailing_zeros(value: int) -> int:
    """Returns the number of trailing zeros in the binary representation of
    the given integer.
    """
    num_zeros = 0
    while value & 1 == 0:
        num_zeros += 1
        value >>= 1
    return num_zeros

def next_power_of_two(value: int) -> int:
    """Returns the smallest power of two that is greater than or equal
    to the given integer.
    """
    if value < 0:
        raise ValueError("Negative integers not supported")
    return 1 if value == 0 else 1 << ceil(log2(value))
