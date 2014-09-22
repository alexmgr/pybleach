from __future__ import with_statement
import timeit
import os
import urllib, urllib2, cookielib
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
    """
    >>> o = Oracle()
    >>> o.query(123, None)
    Traceback (most recent call last):
    NotImplementedError: Override this method to query the padding oracle
    """
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

class HttpOracle(Oracle):

  def __init__(self, url, get={}, post=None, headers=None):
    super(Oracle, self).__init__()
    if url == None:
      raise ValueError("URL cannot be empty")
    self.url = url
    self.get = get
    self.post = post
    self.headers = headers

  def __do_http_request(self, url, c=None):
    """ Ugly code to deal with most situations
    REFACTOR!!!!
    """
    if self.get != {}:
      url = "%s?%s" % (url, urllib.urlencode(self.__insert_ciphertext(c, self.get)))
    else:
      url = self.url
    
    if c != None:
      post = self.__insert_ciphertext(c, self.post)
      headers = self.__insert_ciphertext(c, self.headers)
    else:
      post = self.post
      headers = self.headers

    if post == None and headers == None:
      req = urllib2.Request(url)
    elif post != None:
      req = urllib2.Request(url, urllib.urlencode(post))
    elif headers != None:
      req = urllib2.Request(url, headers=headers)
    else:
      req = urllib2.Request(url, urllib.urlencode(post), headers)
    
    resp = None
    try:
      with OracleTimer() as timer:
        try:
          resp = urllib2.urlopen(req)
        except urllib2.HTTPError as he:
          resp = he
    finally:
        duration = timer.duration
    return resp, duration

  def set_cookie(self, cookie_url):
    """ Sets the cookie by querying the remote site
    >>> ho = HttpOracle("https://www.google.com")
    >>> ho.set_cookie()
    >>> [True for cookie in ho.cookie_jar if "google" in cookie.domain]
    [True, True]
    """
    self.cookie_jar = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cookie_jar))
    urllib2.install_opener(opener)
    self.__do_http_request(cookie_url)

  def __insert_ciphertext(self, c, template):
    """ Inserts the ciphertext value into the template
    >>> get_values = {"param1":"some_stuff", "param2":"blah => %s"}
    >>> ho = HttpOracle("http://www.w3c.org", get_values)
    >>> sub = ho._HttpOracle__insert_ciphertext("ciphertext", get_values)
    >>> len(sub) == len(get_values)
    True
    >>> sub["param2"] == "blah => ciphertext"
    True
    """
    values = None
    if template != None:
      values = {}
      for k, v in template.iteritems():
        try:
          values[k] = v % c
        except TypeError:
          values[k] = v
    return values

  def set_proxy(self, proxies=None):
    if proxies == None:
      proxy = urllib2.ProxyHandler()
    else:
      proxy = urllib2.ProxyHandler(proxies)
    opener = urllib2.build_opener(proxy)
    urllib2.install_opener(opener)

  def query(self, c, callback):
    """ Perform http request to the oracle. Get http response back as well as timing
    >>> def callback(resp, duration):
    ...   # dict(resp.info()) to get headers
    ...   return resp.getcode(), duration
    >>> get_values = {"param1":"some_stuff", "param2":"blah => %s"}
    >>> ho = HttpOracle("http://www.w3c.org", get_values)
    >>> resp = ho.query("123456789", callback)
    >>> resp[0]
    200
    """
    try:
      resp, query_duration = self.__do_http_request(self.url, c)
    except urllib2.URLError as ue:
      # TODO add logging
      resp = None
      query_duration = -1
    return callback(resp, query_duration)

if __name__ == "__main__":
  import doctest
  doctest.testmod()
