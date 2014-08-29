from __future__ import with_statement
from math import ceil, log
from oracle import Oracle
from Crypto.PublicKey import RSA

class NumUtils(object):
  
  @staticmethod
  def to_int(val):
    """Converts a value to base 10. If base 10 fails, try base 16.
    >>> NumUtils.to_int(1234) == 1234
    True
    >>> NumUtils.to_int("1234") == 1234
    True
    >>> NumUtils.to_int("abcd") == 0xabcd
    True
    >>> NumUtils.to_int(0xabcd) == 0xabcd
    True
    >>> NumUtils.to_int("abcdgh")
    >>> NumUtils.to_int(5.56)
    5
    """
    num = None
    try:
      num = int(val)
    except ValueError:
      try:
        num = int(val, 16)
      except ValueError as ve:
        num = None
    return num
  
  @staticmethod
  def to_int_error(val, prefix):
    num = NumUtils.to_int(val)
    if num == None:
      raise ValueError("%s must be an integer" % prefix)
    else:
      return num

  @staticmethod
  def pow2_round(val):
    """Rounds a number to the nearest power of two
    >>> NumUtils.pow2_round(255)
    256
    >>> NumUtils.pow2_round(34)
    64
    >>> NumUtils.pow2_round(0)
    Traceback (most recent call last):
    ValueError: Number to round must be a positive integer
    >>> NumUtils.pow2_round(-1)
    Traceback (most recent call last):
    ValueError: Number to round must be a positive integer
    """
    if val <= 0:
      raise ValueError("Number to round must be a positive integer")
    num = NumUtils.to_int_error(val, "Value to round")
    return int(pow(2, ceil(log(num) / log(2))))
  
  @staticmethod
  def bits_to_hold(val, unit=1):
    """Returns the number of bits needed to hold number val
    >>> NumUtils.bits_to_hold(1234)
    11
    >>> NumUtils.bits_to_hold(1234, 8)
    1
    >>> NumUtils.bits_to_hold(93363501535823485560286011140434660057766656356767952260224292233143073609873L)
    256
    >>> NumUtils.bits_to_hold(93363501535823485560286011140434660057766656356767952260224292233143073609873L, 8)
    32
    """
    num = NumUtils.to_int_error(val, "Value to inspect")
    return int(ceil(log(num) / log(2)) / unit)

  @staticmethod
  def bytes_to_hold(val):
    return NumUtils.bits_to_hold(val, 8)  

class Bleichenbacher(object):
  
  def __init__(self, n, c, oracle, e=0x10001):
    """ Builds an object to compute the Bleichenbacher attack
    >>> b = Bleichenbacher(1234123412341234, "abcdef", None)
    Traceback (most recent call last):
    ValueError: Padding oracle must be a valid object
    >>> b = Bleichenbacher(1234123412341234, "abcdef", int())
    >>> b.n
    1234123412341234
    >>> b.c == int("abcdef", 16)
    True
    >>> b.k 
    64
    >>> hex(b.B2)[:3] == "0x2"
    True
    >>> hex(b.B3)[:5] == "0x2ff"
    True
    """
    self.n = NumUtils.to_int_error(n, "Modulus")
    self.c = NumUtils.to_int_error(c, "Ciphertext")
    bits_needed = NumUtils.bytes_to_hold(self.n) * 8
    self.k = NumUtils.pow2_round(bits_needed)
    self.B = 2**(self.k - 16)
    self.B2 = 2*self.B
    self.B3 = 3*self.B - 1
    if oracle == None:
      raise ValueError("Padding oracle must be a valid object")

  @classmethod
  def pubkey_from_file(cls, key_file, c, oracle):
    """Imports modulus and exponent information from a pem key file
    >>> a = lambda i: i
    >>> b = Bleichenbacher.pubkey_from_file("256.pub", "123456", a)
    >>> b.n
    93363501535823485560286011140434660057766656356767952260224292233143073609873L
    >>> b.c == int("123456", 10)
    True
    >>> b.k
    256
    """
    with open(key_file, 'r') as kf:
      key_pair = RSA.importKey(kf.read())
    b = cls(key_pair.n, c, oracle, key_pair.e)
    return b

if __name__ == "__main__":
  import doctest
  doctest.testmod()  
