from __future__ import with_statement
import multiprocessing as mp
import threading as th
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
    self.s1_search_running = False
    if oracle == None:
      raise ValueError("Padding oracle must be a valid object")
    else:
      self.oracle = oracle

  @classmethod
  def pubkey_from_file(cls, key_file, oracle):
    """Imports modulus and exponent information from a pem key file
    >>> o = Oracle()
    >>> b = Bleichenbacher.pubkey_from_file("keypairs/256.pub", o)
    >>> b.n
    93363501535823485560286011140434660057766656356767952260224292233143073609873L
    >>> b.k
    256
    """
    with open(key_file, 'r') as kf:
      key_pair = RSA.importKey(kf.read())
    b = cls(key_pair.n, oracle, key_pair.e)
    return b

  def __s1_job_completed(self, args):
    """Called each time the processing is finished by a member of the pool"""
    if args[0] == True:
      self.s1_search_running = False
      self.s1 = args[1]      
      print("s1 found in %i iterations: %i" % (args[2], args[1]))

  def __do_s1_oracle_query(self, c, s1, i, callback):
    """ The worker in charge of calling the oracle to test the padding """
    # This is c*E(s1) = c * (s1**e % n) % n = (c * (s1**e)) % n
    c_prime = (c * (s1**self.e)) % self.n
    print("i = %i => s1 = %i => c' = %064x" % (i, s1, c_prime))
    return (self.oracle.query(c_prime, callback), s1, i)

  def s1_search(self, c, callback, pool_size=mp.cpu_count()):
    """
    >>> def callback(stdout, stderr, rc):
    ...   return True if rc != 2 else False
    >>> o = ExecOracle("./pkcs1_test_oracle.py", ["keypairs/1024.priv", "%0256x"])
    >>> b = Bleichenbacher.pubkey_from_file("keypairs/1024.pub", o)
    >>> b.s1_search("1234abcdh", callback)
    Traceback (most recent call last):
    ValueError: Ciphertext must be an integer
    >>> # ./rsa_test_client.py 1024.pub $(python -c 'print "000201020304050607080900" + "41"*116')
    >>> b.s1_search("6c1d38dbcb5c0ab72324618ce93f646c842aa7029920722c14570a0d856219f778620850c57c69dc0e41923c8696d8494c846f8f2bf4f0e8d5ce4c865c624f438a70f927b77aa72628fd05bd5d7853d0d859f27b95428c9d6d16fab1ef46509051fdceb97ee0f8192e91115bc29a703278b7a95a22b90ecd5c8015d019e35b8e", callback) # doctest: +SKIP
    (42298L, 28172) 
    """
    c = NumUtils.to_int_error(c, "Ciphertext")
    s1 = NumUtils.ceil_int(self.n, self.B3)
    self.s1_search_running = True
    pool = mp.Pool(pool_size)
    i = 1
    while self.s1_search_running:
      pool.apply_async(self.__do_s1_oracle_query, (c, s1, i, callback, ), callback=self.__s1_job_completed)
      i += 1
      s1 += 1
    pool.close()
    return s1, i

  def __get_r_interval(self, s, interval):
    """returns the values of r for a given s/interval couple
    >>> o = ExecOracle("./pkcs1_test_oracle.py", ["keypairs/1024.priv", "%0256x"])
    >>> b = Bleichenbacher.pubkey_from_file("keypairs/1024.pub", o)
    >>> # Calling private method through name mangling. Not sure how to test with doctest otherwise
    >>> b._Bleichenbacher__get_r_interval(42298L, (1, 2, 3))
    Traceback (most recent call last):
    ValueError: An interval must contain 2 values only
    >>> b._Bleichenbacher__get_r_interval(42298L, (2, 1))
    Traceback (most recent call last):
    ValueError: The interval upper boundary must be superior to the lower boundary
    >>> b._Bleichenbacher__get_r_interval(42298L, (b.B2, b.B3))
    [2]
    """
    if len(interval) != 2:
      raise ValueError("An interval must contain 2 values only")
    a = interval[0]
    b = interval[1]
    if (a > b):
      raise ValueError("The interval upper boundary must be superior to the lower boundary")
    r_min = NumUtils.ceil_int((a * s - self.B3 + 1), self.n)
    r_max = NumUtils.floor_int((b * s - self.B2), self.n)
    return [r for r in range(r_min, r_max + 1)]

if __name__ == "__main__":
  import doctest
  doctest.testmod()  
