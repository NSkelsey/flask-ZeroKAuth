import random
from binascii import hexlify
import os
import hashlib


def randbits(n=512):
    """input number of bits and get back that many random bits as a long"""
    return long(random.SystemRandom().getrandbits(n))


def _hash(*args):
    """returns a long of the encoded params
    which are either strings, longs or ints. 
    """
    def upd(acc, val):
        typ = type(val)
        assert typ == int or typ == str or typ == long
        if typ == int or typ == long:
            acc += _hex(val)
        else:
            acc += val
        return acc
    hashp = reduce(upd, args, "")
 #  print "="*50
 #  print hashp
 #  print "="*50
    digest = hashlib.sha256(hashp).hexdigest()
    return long(digest, 16)

def group_constants():
    """Returns the defined group constants for our implementation"""
    # N must have all capital letters
    N = """EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"""
    g = 2
    N = int(N, 16)
    k = _hash(N, g)
    return (N, g, k)

def _hex(val):
    """Takes an integer or a long and removes python's hex formatting
    returning just the hex vals and nothing more"""
    typ = type(val)
    assert typ == long or typ == int
    if typ == long:
        return hex(val)[2:-1]
    else:
        return hex(val)[2:]


if __name__ == '__main__':
    N, g, k = group_constants()
    print "K:\t%d" % (k)

