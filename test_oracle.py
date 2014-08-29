#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from binascii import hexlify, unhexlify
from math import ceil, log
from sys import argv, exit, stderr
from Crypto.PublicKey import RSA

pow2_round = lambda i: int(pow(2, ceil(log(i)/log(2))))

rsa = RSA.importKey(open(argv[1]).read())
k = pow2_round(rsa.size() / 8)
m = rsa.decrypt(unhexlify(argv[2]))

error = 0
if len(m) != k:
  print("Message too short. Appending %i null bytes" % (k - len(m)), file=stderr)
  m = "%s%s" % ("\x00" * (k - len(m)), m) 

header = m[:2]
m_with_padding = m[2:]
mandatory_padding = m[2:10]

if header != "\x00\x02":
  print("Error: m does not start with 0x0002: %s" % hexlify(header), file=stderr)
  error = 2 
elif "\x00" in mandatory_padding:
  print("Error: m contains 0x00 within mandatory 8 padding bytes: %s" % hexlify(mandatory_padding), file=stderr)
  error = 3
elif "\x00" not in m_with_padding:
  print("Error: m does not contain a 0x00 padding delimiter", file=stderr)
  error = 4
else:
  try:
    print(m[m.index("\x00", 2) + 1:])
  except ValueError as ve:
    print("Error: Looks like I forgot a test case! Sorry ;): %s" % ve)
exit(error)
