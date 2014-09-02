from __future__ import with_statement
from math import ceil, log
import multiprocessing as mp
from oracle import Oracle, ExecOracle
from Crypto.PublicKey import RSA
from utils import NumUtils

class Bleichenbacher(object):
  
  def __init__(self, n, oracle, e=0x10001):
    """Builds an object to compute the Bleichenbacher attack
    >>> b = Bleichenbacher(1234123412341234, None)
    Traceback (most recent call last):
    ValueError: Padding oracle must be a valid object
    >>> b = Bleichenbacher(1234123412341234, int())
    >>> b.n
    1234123412341234
    >>> b.k 
    64
    >>> hex(b.B2)[:3] == "0x2"
    True
    >>> hex(b.B3)[:5] == "0x2ff"
    True
    """
    self.n = NumUtils.to_int_error(n, "Modulus")
    bits_needed = NumUtils.bytes_to_hold(self.n) * 8
    self.k = NumUtils.pow2_round(bits_needed)
    self.e = NumUtils.to_int_error(e, "Exponent")
    self.B = 2**(self.k - 16)
    self.B2 = 2*self.B
    self.B3 = 3*self.B - 1
    if oracle == None:
      raise ValueError("Padding oracle must be a valid object")
    else:
      self.oracle = oracle

  @classmethod
  def pubkey_from_file(cls, key_file, oracle):
    """Imports modulus and exponent information from a pem key file
    >>> o = Oracle()
    >>> b = Bleichenbacher.pubkey_from_file("256.pub", o)
    >>> b.n
    93363501535823485560286011140434660057766656356767952260224292233143073609873L
    >>> b.k
    256
    """
    with open(key_file, 'r') as kf:
      key_pair = RSA.importKey(kf.read())
    b = cls(key_pair.n, oracle, key_pair.e)
    return b

  def start_search(self, c, callback):
    """
    >>> def callback(stdout, stderr, rc):
    ...   return True if rc == 0 else False
    >>> o = ExecOracle("./pkcs1_test_oracle.py", ["256.priv", "%x"])
    >>> b = Bleichenbacher.pubkey_from_file("256.pub", o)
    >>> b.start_search("1234abcdh", callback)
    Traceback (most recent call last):
    ValueError: Ciphertext must be an integer
    >>> # ./rsa_test_client.py 256.pub $(python -c 'print "000201020304050607080900" + "41"*20')
    >>> b.start_search("12b8b8d3e15c49f2638a99be4184260cf8236c12bddc7ead9fd3b95578772588", callback)
    (17614L, 1)
    """
    c = NumUtils.to_int_error(c, "Ciphertext")
    s1 = NumUtils.ceil_int(self.n, self.B3)
    i = 1
    while True:
      # This is c*E(s1) = c * (s1**e % n) % n = (c * (s1**e) %n)
      m1 = (c * (s1**self.e)) % self.n
      print("m1: %064x" % m1)
      if self.oracle.query(m1, callback):
        break
      i += 1
      s1 += 1
    return s1, i

if __name__ == "__main__":
  def callback(stdout, stderr, rc):
    print(stdout, stderr, rc)
    return True if rc != 2 else False
  o = ExecOracle("./pkcs1_test_oracle.py", ["256.priv", "%064x"])
  b = Bleichenbacher.pubkey_from_file("256.pub", o)
  z = b.start_search("12b8b8d3e15c49f2638a99be4184260cf8236c12bddc7ead9fd3b95578772588", callback)
  print(z)
  import doctest
  #doctest.testmod()  
