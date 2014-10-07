#!/usr/bin/env python
# -*- coding: utf-8 -*-

from os import linesep
from argparse import ArgumentParser, FileType
from sys import stdin
from oracle import HttpOracle

def parse_arguments():
  parser = ArgumentParser(description="A simple HTTP client used to test server responses to padding errors")
  parser.add_argument("ciphertext", help="The ciphertext to record the response for. If not provided, stdin is assumed", type=str, default='-', nargs='?')
  parser.add_argument("-u", "--url", help="The url to test the padding faults against", required=True)
  parser.add_argument("-n", "--noproxy", help="Do not use a proxy. The http(s)_proxy environment variable will be ignored in this case. Default is to consider the environment variable", action="store_false")
  parser.add_argument("-i", "--iterations", help="Number of times to run the test for a single entry. Helps get more consistent time results", type=int, default=5)
  parser.add_argument("-x", "--headers", help="The headers to set in the request. Format is a list of comma separated key=value pairs. A valueless key entry is also accepted", default="")
  parser.add_argument("-p", "--post", help="The post parameters to set in the request. Format is a list of comma separated key=value pairs. A valueless key entry is also accepted", default="")
  return parser

def kv_pairs_to_dict(free_form_str):
  kv = {}
  pairs = free_form_str.split(',')
  for pair in pairs:
    items = pair.split('=', 1)
    try:
      kv[items[0]] = items[1]
    except IndexError:
      kv[items[0]] = ""
  return kv

def http_response_parser(response, query_duration):
  print("\tCode: % 8d\tDuration: % 8f" % (response.code, query_duration))

if __name__ == "__main__":
  parser = parse_arguments()
  args = parser.parse_args()

  if args.ciphertext != '-':
    ciphertext = [args.ciphertext]
  else:
    ciphertext = [ciphertext.strip(linesep) for ciphertext in stdin.readlines()]

  http_client = HttpOracle(args.url)

  if not args.noproxy:
    http_client.set_proxy()

  headers = args.headers
  if headers != "":
    http_client.headers = kv_pairs_to_dict(headers)

  post = args.post
  if post != "":
    http_client.post = kv_pairs_to_dict(post)

  for c in ciphertext:
    print(c)
    for _ in xrange(args.iterations):
      http_client.query(c, http_response_parser)
