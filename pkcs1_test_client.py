#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from argparse import ArgumentParser, FileType
from binascii import hexlify, unhexlify
from os import linesep
from sys import stdin, stderr
from Crypto.PublicKey import RSA
from padding import PKCS1_v15
from utils import NumUtils

def parse_arguments():
  parser = ArgumentParser(description="A PKCS1 v1.5 client, to test responses to various padding conditions")
  parser.add_argument("cleartext", help="The cleartext to PKCS1 v1.5 pad or encrypt. If not provided, stdin is assumed", type=str, default='-', nargs='?')
  parser.add_argument("-x", "--hex", help="Consider the cleartext as a hex encoded string. Default is false", action="store_true")
  parser.add_argument("-c", "--clear", help="Output the cleartext message instead of the encrypted one. Default is false with -f", action="store_false")
  length_group = parser.add_mutually_exclusive_group(required=True)
  length_group.add_argument("-l", "--length", help="The length of the RSA modulus in bits", type=int)
  length_group.add_argument("-f", "--pubkey", help="The PEM file containing the public key", type=FileType('r'))
  choice_group = parser.add_argument_group("Padding Test", "The padding tests to run (multiple choice possible). Each message will be output on a seperate line")
  choice_group.add_argument("-1", "--cm", help="Generate a valid PKCS1 v1.5 padded message", dest="tests", action="append_const", const=1)
  choice_group.add_argument("-2", "--cnb", help="Generate a valid PKCS1 v1.5 padded message which contains multiple conecutive null-bytes", dest="tests", action="append_const", const=2)
  choice_group.add_argument("-3", "--nch", help="Generate a non-conforming PKCS1 v1.5 padded message. Message will start with 0x0001, expected 0x0002", dest="tests", action="append_const", const=3)
  choice_group.add_argument("-4", "--ncl", help="Generate a non-conforming PKCS1 v1.5 padded message. Message will contain a null-byte within the 8 bytes of random padding", dest="tests", action="append_const", const=4)
  choice_group.add_argument("-5", "--ncd", help="Generate a non-conforming PKCS1 v1.5 padded message. Message will not contain a null-byte delimiter", dest="tests", action="append_const", const=5)
  choice_group.add_argument("-a", "--all", help="Generate all test cases", dest="tests", action="store_const", const=(1,2,3,4,5))
  return parser

if __name__ == "__main__":

  parser = parse_arguments()
  args = parser.parse_args()

  if args.cleartext != '-':
    cleartexts = [args.cleartext]
  else:
    cleartexts = [cleartext.strip(linesep) for cleartext in stdin.readlines()]
  
  print_encrypted = args.clear

  if args.tests == None:
    tests = (1,)
  else:
    tests = set(args.tests)

  if args.pubkey != None:
    try:
      rsa = RSA.importKey(args.pubkey.read())
      k = NumUtils.pow2_round(rsa.size())
    except Exception as ex:
      print("Can't load public key from file %s: " % args.pubkey.name, ex, file=stderr)
      parser.print_help()
      exit(1)
  else:
      print_encrypted = False

  if args.length != None:
    k = NumUtils.pow2_round(args.length)

  if args.hex:
    try:
      cleartexts = [unhexlify(cleartext) for cleartext in cleartexts]
    except TypeError as te:
      print("Cleartext provided is not in hex format: %s: " % cleartext, te, file=stderr)
      parser.print_help()
      exit(1)

  pkcs1 = PKCS1_v15(k)
  for m in cleartexts:
    for i in tests:
      padded_cleartext = getattr(pkcs1, PKCS1_v15.FUNC_TABLE[i])(m)
      if print_encrypted:
        c = rsa.encrypt(padded_cleartext, 0)[0]
        c = "\x00"*(k/8-len(c)) + c
        print(hexlify(c))
      else:
        print(hexlify(padded_cleartext))

