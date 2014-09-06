#!/usr/bin/env python
# -*- coding: utf-8 -*-

import copy_reg
from types import MethodType
from oracle import ExecOracle
from padding import Bleichenbacher

if __name__ == "__main__":
  try:
    def callback(stdout, stderr, rc):
      #print("From user callback", stdout, stderr, rc)
      return True if rc != 2 else False
    o = ExecOracle("./pkcs1_test_oracle.py", ["keypairs/1024.priv", "%0256x"])
    b = Bleichenbacher.pubkey_from_file("keypairs/1024.pub", o, callback)
    s1, i = b.run_search("6c1d38dbcb5c0ab72324618ce93f646c842aa7029920722c14570a0d856219f778620850c57c69dc0e41923c8696d8494c846f8f2bf4f0e8d5ce4c865c624f438a70f927b77aa72628fd05bd5d7853d0d859f27b95428c9d6d16fab1ef46509051fdceb97ee0f8192e91115bc29a703278b7a95a22b90ecd5c8015d019e35b8e")
    print("Found s1 :%i in %i iterations" % (s1, i))
  except KeyboardInterrupt:
    b.stop_search()
