# OSCORE Interop 7 Report

Starting on 7th of Dec 2018, 09:00 CET (several days)

## Participants

- Martin Gunnarsson
- Rikard Höglund
- Francesca Palombini

## Note takers

Francesca

## Documentation

### \[1\]: [Test specification provided](test-spec5.html)

### \[2\]: [OSCORE version implemented](https://tools.ietf.org/html/draft-ietf-core-object-security-15)

## Summary

This 7th interop was carried on after IETF103. Two implementers participated: Martin and Rikard, with implementations based on OSCORE v-15 (see \[2\]). Rikard participated with a Java implementation based on Californium CoAP, Martin with a C implementation based on Contiki.

The result is summarized in the table below:

+-----------+-----------+-----------+------------------+
|    round  |   Client  |   Server  |      Result      |
+:=========:+:=========:+:=========:+:================:+
| [1](#RM)  |  Rikard   |  Martin   |      Passed      |
+-----------+-----------+-----------+------------------+
| [2](#MR)  |  Martin   |  Rikard   |      Passed      |
+-----------+-----------+-----------+------------------+

The outcome of each test during the run was marked as successful (passed), if the outcome was the one expected according to the test specification \[1\], not implemented, if either of the implementations did not implement or could not run the test, or failed, if the two implementations did not agree on the output of each test. 

<!--
The traffic was also captured and shared it with us, to allow for a more extensive analysis of the results.
-->

Tests with Observe (5 to 7) were not completed, since the implementations do not have Observe implementations.
Some tests did pass with some inconsistencies with the test specification, but the OSCORE outcome was the expected, so they are considered passed.
In short, this interop for OSCORE was successful, and we will run a follow up interop to test the rest of the Observe code when that is added to the implementation.
-->

## Details

### notes:

Some time was taken initially to make the Java code run on Martin's machine. Then some more time was taken to set up the environment (so that the compiler did not take all the warnings as errors). Then some time to make the border router work.


### 1. Client: Rikard, Server: Martin {#RM}

* 0\. Passed
* 1\. Problem on the client to use the IPv6 string as URI to set up the context. Set up a local uri. Now the client works, the server fails in the option number. Then when that was fixed, decryption of request failed on the server, both client and server had wrong aad. After fixing that, and fixing the length on encrypt. After fixing a nonce problem in the response on the server side, Passed.
* 2\. Passed after implementing the different sec ctx on Server
* 3\. Passed
* 4\. Passed after fixing OSCORE option order on server
* 5\. Not implemented on client and server
* 6\. Not implemented on client and server
* 7\. Not implemented on client and server
* 8\. Passed
* 9\. Passed
* 10\. Paseed
* 11\. Passed
* 12\. Passed
* 13\. Passed
* 14\. Passed
* 15\. Passed
* 16\. Not implemented
* 17\. Passed

### 2. Client: Martin, Server: Rikard {#MR}

* 0\. Passed
* 1\. Passed
* 2\. Passed
* 3\. Passed
* 4\. Passed
* 5\. Not implemented on client and server
* 6\. Not implemented on client and server
* 7\. Not implemented on client and server
* 8\. Passed
* 9\. Passed
* 10\. Passed
* 11\. Passed
* 12\. Passed
* 13\. Passed
* 14\. Passed
* 15\. Passed
* 16\. Passed
* 17\.Passed

## Feedback on Test Specifications and Issues

A point was reised on the test specifications:

* Test 14 specifies that an ACK should be sent. That is CoAP behavior independent from OSCORE, and it is not always the case that the ACK will be sent (see piggibacked response). An issue was created on OSCORE to fix the ambiguity between an error that comes from not recognizing OSCORE and an error that comes from OSCORE processing (same code 4.02): https://github.com/core-wg/oscoap/issues/254

