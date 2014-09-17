#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from argparse import ArgumentParser, ArgumentTypeError, FileType
from binascii import hexlify, unhexlify
import random
from sys import argv, stderr
from Crypto.PublicKey import RSA
from utils import NumUtils

class PKCS1_v15(object):

  HEADER = "\x00\x02"
  DELIMITER = "\x00"
  MIN_PAD_LEN = 8
  MIN_LEN = len(HEADER) + MIN_PAD_LEN + len(DELIMITER)

  def __init__(self, key_length):
    self.k = key_length

  def get_random_padding(self, data):
    return self.__get_random_bytes(data, ["\x00"])

  def conforming_message(self, data):
    padding_len = self.k - len(data) - len(PKCS1_v15.HEADER) - len(PKCS1_v15.DELIMITER)
    if padding_len < PKCS1_v15.MIN_PAD_LEN:
      raise ValueError("Cleartext too long to be conforming: max => %i bytes, provided => %i bytes" % (self.k - PKCS1_v15.MIN_LEN, len(data)))
    random_padding = self.get_random_padding(padding_len)
    return PKCS1_v15.HEADER + random_padding + PKCS1_v15.DELIMITER + data

  def conforming_consecutive_null_bytes(self, data, index=-1, extra_nulls=2, pad_back=True):
    padded_m = self.conforming_message(data)
    if index == -1:
      index = padded_m.index("\x00", 1) + 1
    if pad_back == True:
      index -= (extra_nulls + 1)
    if index < 0 or index >= self.k or index + extra_nulls >= self.k:
      raise IndexError("Cannot pad null bytes passed data boundary")
    return padded_m[:index] + "\x00"*extra_nulls + padded_m[index + extra_nulls:]

  def non_conforming_message_header(self, data, header="\x00\x01"):
    return header + self.conforming_message(data)[2:]

  def non_conforming_padding_length(self, data, byte_index=4):
    padded_m = self.conforming_message(data)
    abs_pos = len(PKCS1_v15.HEADER) + byte_index - 1
    return padded_m[:abs_pos] + "\x00" + padded_m[abs_pos + 1:]

  def non_conforming_no_delimiter(self, data, replacement="\xff"):
    padded_m = self.conforming_message(data)
    null_index = padded_m.index("\x00", 1)
    return padded_m[:null_index] + replacement + padded_m[null_index + 1:]

  def __get_random_bytes(self, length, excluded=[]):
    random_gen = random.Random()
    random_bytes = ""
    while (len(random_bytes) != length):
      # counter-intuitive: max boundary 0xff included
      random_byte = chr(random_gen.randint(0x0, 0xff))
      if random_byte not in excluded:
        random_bytes += random_byte
    return random_bytes

def parse_arguments():
  parser = ArgumentParser(description="A PKCS1 v1.5 client, to test responses to various padding conditions")
  parser.add_argument("cleartext", help="The cleartext to PKCS1 v1.5 pad or encrypt", type=str)
  parser.add_argument("-x", "--hex", help="Consider the cleartext as a hex encoded string. Default is false", action="store_true")
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
  print_encrypted = False
  func_table = {1:"conforming_message",
                2:"conforming_consecutive_null_bytes",
                3:"non_conforming_message_header",
                4:"non_conforming_padding_length",
                5:"non_conforming_no_delimiter"
                }

  parser = parse_arguments()
  args = parser.parse_args()
  
  if args.tests == None:
    tests = (1,)
  else:
    tests = set(args.tests)

  if args.pubkey != None:
    try:
      rsa = RSA.importKey(args.pubkey.read())
      k = NumUtils.pow2_round(rsa.size()) / 8
      print_encrypted = True
    except Exception as ex:
      print("Can't load public key from file %s: " % args.pubkey, ex, file=stderr)
      parser.print_help()
      exit(1)

  if args.length != None:
    k = NumUtils.pow2_round(args.length) / 8

  if args.hex:
    try:
      m = unhexlify(args.cleartext)
    except TypeError as te:
      print("Cleartext provided is not in hex format: ", te, file=stderr)
      parser.print_help()
      exit(1)
  else:
    m = args.cleartext

  pkcs1 = PKCS1_v15(k)
  for i in tests:
    padded_cleartext = getattr(pkcs1, func_table[i])(m)  
    if print_encrypted:
      c = rsa.encrypt(padded_cleartext, 0L)
      print(hexlify(c[0]))
    else:
      print(hexlify(padded_cleartext))

