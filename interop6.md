# OSCOAP Interop 6 Report

27th of July 2018, 17:00-19:00 CEST

## Participants

- Christian Amsüss
- Jim Schaad
- Francesca Palombini

## Note takers

Francesca

## Documentation

### \[1\]: [Test specification provided](test-spec5.html)

### \[2\]: [OSCOAP version implemented](https://tools.ietf.org/html/draft-ietf-core-object-security-14)

## Summary

This 6th interop was carried on after IETF102. Two implementers participated: Christian and Jim, with implementations based on OSCORE v-14 (see \[2\]).

The result is summarized in the table below:

+-----------+-----------+-----------+------------------+
|    round  |   Client  |   Server  |       Result     |
+:=========:+:=========:+:=========:+:================:+
| [1](#CJ)  | Christian |    Jim    |      Passed      |
+-----------+-----------+-----------+------------------+
| [2](#JC)  |    Jim    | Christian |      Passed      |
+-----------+-----------+-----------+------------------+

The outcome of each test during the run was marked as successful (passed), if the outcome was the one expected according to the test specification \[1\], not implemented, if either of the implementations did not implement or could not run the test, or failed, if the two implementations did not agree on the output of each test. The traffic was also captured and shared it with us, to allow for a more extensive analysis of the results.

Tests with Observe (6 and 7) were not fully completed correctly, since the implementations do not have correct Observe implementations (in particular the cancellation part), but the OSCORE part did not fail, so they are not considered failed. 

Some tests did pass with some inconsistencies with the test specification, but the OSCORE outcome was the expected, so they are considered passed.

In short, this interop for OSCORE was successful, and we will run a follow up interop to test the rest of the Observe code.

## Details

### notes:

The interop was recorded and can be found here: https://www.youtube.com/watch?v=uf4sBRlEYH0

#### Chat from Jitsi

francesca16:58:56
here
Christian16:59:01
coap://prometheus.amsuess.com/
jimsch17:00:00
coap://jimsch.hopto.org
Christian17:14:10
my external AAD:
Christian17:14:11
8501810a40410540
jimsch17:14:42
3A-30-E8-9F-42-80-04-FA-D4-D7-AD-90-4A-BB-D1-92
jimsch17:20:56
[0]: 133
[1]: 65
[2]: 1
[3]: 246
[4]: 10
[5]: 99
[6]: 75
[7]: 101
[8]: 121
[9]: 16
jimsch17:24:21
[0]: 0x45
[1]: 0xc3
[2]: 0x88
[3]: 0x22
[4]: 0xfc
[5]: 0x55
[6]: 0xea
[7]: 0xc5
Christian17:27:50
8501810a40410040
Christian17:38:35
Decoding with recipient key e39a0c7c77b43f03b4b39ab9a268699f aad 8368456e63727970743040488501810a40410240 nonce 2da58fb85ff1b81d0b7181b85c
jimsch17:39:17
2D-A5-8F-B8-5F-F1-B9-1C-0B-71-81-B8-5C
Christian17:42:41
01000000000000010000000004
Christian17:43:21
01-00-00-00-00-00-00-01-00-00-00-00-04
jimsch17:44:14
ivSize - 5 - entityId.Length - 1
jimsch17:44:55
if (ivSize - 6 < entityId.Length) throw new Exception("Entity id is too long");
ctx.BaseIV[0] ^= (byte) entityId.Length;
int i1 = ivSize - 5 - entityId.Length - 1;
for (int i = 0; i < entityId.Length; i++) ctx.BaseIV[i1 + i] ^= entityId[i];
francesca17:46:21
http://etherpad.tools.ietf.org:9000/p/notes-OSCORE-interop
jimsch17:48:37
01 00 00 00 00 00 01 00 00 00 00 00 00
Christian18:22:36
sorry, gotta restart my browser...
Christian @pegasus18:26:04
Hm, back on another device, but no sound yet...

### 1. Client: Christian, Server: Jim {#CJ}

* 0\. Initial no response (changed adress on Jim's side). Fixed that, then passed.
* 1\. Christian got method not allowed (because of option number? Jim had 21, Christian 9). Then Bad request with decryption failure. Jim's salt was not the same as in the test spec. Typo in master salt on Server's side. Passed after fixed.
* 2\. Passed after fixed nonce (offset for Jim was not correct)
* 3\. Passed
* 4\. Passed 
* 5\. Passed 
* 6\. Jim observe does not handle cancellations
* 7\. Christian cannot cancel (Observe implementation code missing)
* 8\. passed with inconsistencies with test spec from server side
* 9\. passed with inconsistencies with test spec from server side
* 10\. passed 
* 11\. passed 
* 12\. passed (with an implementation error in Client's side)
* 13\. passed
* 14\. passed
* 15\. passed
* 16\. non implemented
* 17\. passed after fixed test inconsistencies from client side

### 2. Client: Jim, Server: Christian {#CJ}

* 0\. Passed
* 1\. Passed
* 2\. Inconsistencies because of test spec: Jim is expecting ID Context, Christian doesn't send it. OSCORE does not specify this. This might be needed in group OSCORE draft. Or application.
* 3\. Passed
* 4\. Passed
* 5\. Passed
* 6\. Christian updates his server. Then Jim doesn't find the right context via the token
* 7\. Not implemented on Clients side
* 8\. Passed
* 9\. Passed
* 10\. Passed
* 11\. Passed
* 12\. Passed (with some inconsistencies from test implementation Client)
* 13\. Passed
* 14\. Passed
* 15\. Passed but client's code is incorrect
* 16\. non implemented
* 17\. passed after fixed test inconsistencies from client side

## Feedback on Test Specifications and Issues

Several points were raised in the interop about the test specifications, some of which have already been fixed:

* Test 4: Outer Max-Age set to 0 should be optional (fixed)
* Sender Key for Context D was incorrect (fixed)
* Common IV for Context C was incorrect (fixed)
* Test 15: the error returned should be 4.01 Unauthorized and not 4.00 Bad Request
* Test 9: The response should not return a payload and content format
* Test 16: A "Method not allowed" error response is also an acceptable outcome of the test

Additionally, for test 2, the following comment was raised: it is not specified if a Client should expect a ID Context and/or Sender ID back. In fact, that is not part of \[2\] but is application specific. The test specification should have specified that. Moreover, it is to be considered if group OSCORE should add that in the draft itself.

