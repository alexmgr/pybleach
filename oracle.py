from __future__ import with_statement
import timeit
import os
from subprocess import Popen, PIPE
from utils import NumUtils

class OracleTimer(object):
  """
  >>> import time
  >>> with OracleTimer() as ot:
  ...   time.sleep(0.1)
  >>> 0.0 < ot.duration < 0.2
  True
  """

  def __enter__(self):
    self.start = timeit.default_timer()
    return self

  def __exit__(self, *args, **kwargs):
    self.end = timeit.default_timer()
    self.duration = self.end - self.start

class Oracle(object):

  def __init__(self):
    pass
 
  def query(self, c, callback):
    raise NotImplementedError("Override this method to query the padding oracle")

class ExecOracle(Oracle):

  def __init__(self, path, args=[]):
    """
    >>> e = ExecOracle("exe", [])
    Traceback (most recent call last):
    ValueError: exe not found
    >>> from minimock import mock, restore
    >>> import os
    >>> mock("os.path.exists", returns=True)
    >>> e = ExecOracle("exe", [])
    Traceback (most recent call last):
    ValueError: exe must be an executable file
    >>> mock("os.access", returns=True) # doctest: +ELLIPSIS
    C...
    >>> e = ExecOracle("exe", [])
    Called os.path.exists('exe')
    Called os.access('exe', 1)
    >>> e.path == "exe"
    True
    >>> e.args == []
    True
    >>> restore() 
    """
    super(Oracle, self).__init__()
    if os.path.exists(path):
      if os.access(path, os.X_OK):
        self.path = path
      else:
        raise ValueError("%s must be an executable file" % path)
    else:
      raise ValueError("%s not found" % path)
    self.args = args

  def query(self, c, callback):
    """
    >>> def callback(stdout, stderr, ret_code, query_duration):
    ...   return True
    >>> o = ExecOracle("./pkcs1_test_oracle.py", ["keypairs/256.priv", "%064x"])
    >>> o.query("1234abcd", None)
    Traceback (most recent call last):
    ValueError: A callback must be provided to evaluate the output of the oracle
    >>> o.query("1234abcd", callback)
    True
    """
    if callback == None:
      raise ValueError("A callback must be provided to evaluate the output of the oracle") 
    c = NumUtils.to_int_error(c, "Modulus")
    args = [self.path]  
    for arg in self.args:
      try:
        args.append(arg % c)
      except TypeError:
        args.append(arg)
    process = Popen(args, stdout=PIPE, stderr=PIPE)
    with OracleTimer() as timer:
      stdout, stderr = process.communicate()
    rc = process.returncode
    return callback(stdout, stderr, rc, timer.duration)

if __name__ == "__main__":
  import doctest
  doctest.testmod()
