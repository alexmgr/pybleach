#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from binascii import hexlify, unhexlify
from math import ceil, log
from sys import argv
from Crypto.PublicKey import RSA

pow2_round = lambda i: int(pow(2, ceil(log(i)/log(2))))

rsa = RSA.importKey(open(argv[1]).read())
k = pow2_round(rsa.size()) / 8

m = unhexlify(argv[2])

if len(m) != k:
  print("Plaintext not padded? Please pad to %i bytes." % k)
  exit(1)

c = rsa.encrypt(m, 0L)
print(hexlify(c[0]))

