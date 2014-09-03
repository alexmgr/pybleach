from math import ceil, log

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

  @staticmethod
  def ceil_int(x, y):
    """Computes the smallest integer greater or equal to x/y
    >>> NumUtils.ceil_int(10, 5)
    2
    >>> NumUtils.ceil_int(99, 20)
    5
    """
    return x/y + (x%y != 0)

  @staticmethod
  def floor_int(x, y):
    """Returns x/y"""
    return x/y

if __name__ == "__main__":
  import doctest
  doctest.testmod()
