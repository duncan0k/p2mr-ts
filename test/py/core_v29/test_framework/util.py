"""
Stub standing in for Bitcoin Core's test_framework/util.py.

NOT a Core file. The real util.py imports authproxy/coverage (RPC plumbing) that this
offline oracle never touches. messages.py and key.py import only the two names below.
See vectors/SOURCE.md.
"""

import random


def assert_equal(thing1, thing2, *args):
    if thing1 != thing2 or any(thing1 != arg for arg in args):
        raise AssertionError(
            "not(%s)" % " == ".join(str(arg) for arg in (thing1, thing2) + args)
        )


def random_bitflip(data):
    data = list(data)
    data[random.randrange(len(data))] ^= 1 << random.randrange(8)
    return bytes(data)
