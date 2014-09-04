#!/usr/bin/env python
# -*- coding: utf-8 -*-

import copy_reg
from types import MethodType
from oracle import ExecOracle
from padding import Bleichenbacher

def _pickle_method(method):
  func_name = method.im_func.__name__
  obj = method.im_self
  cls = method.im_class
  if func_name.startswith('__') and not func_name.endswith('__'):
    cls_name = cls.__name__.lstrip('_')
    if cls_name:
      func_name = '_%s%s' % (cls_name, func_name)
  return _unpickle_method, (func_name, obj, cls)

def _unpickle_method(func_name, obj, cls):
  for cls in cls.mro():
    try:
      func = cls.__dict__[func_name]
    except KeyError:
      pass
    else:
      break
  return func.__get__(obj, cls)

if __name__ == "__main__":
  # Needed to pickle instance methods!!!
  # See here: http://bytes.com/topic/python/answers/552476-why-cant-you-pickle-instancemethods
  copy_reg.pickle(MethodType, _pickle_method, _unpickle_method)
  def callback(stdout, stderr, rc):
    return True if rc != 2 else False
  o = ExecOracle("./pkcs1_test_oracle.py", ["keypairs/1024.priv", "%0256x"])
  b = Bleichenbacher.pubkey_from_file("keypairs/1024.pub", o)
  s1, i = b.s_search("6c1d38dbcb5c0ab72324618ce93f646c842aa7029920722c14570a0d856219f778620850c57c69dc0e41923c8696d8494c846f8f2bf4f0e8d5ce4c865c624f438a70f927b77aa72628fd05bd5d7853d0d859f27b95428c9d6d16fab1ef46509051fdceb97ee0f8192e91115bc29a703278b7a95a22b90ecd5c8015d019e35b8e", b.s_min_start, callback)
  print("Found s1 :%i in %i iterations" % (s1, i))
