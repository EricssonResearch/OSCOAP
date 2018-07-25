# Tests Specification for OSCORE

[//]: # (use Pandoc : pandoc spec.md -o spec.html)

## Table of Contents
1. [Notes](#notes)
2. [Security Contexts and Resources](#security-contexts-and-resources)
    1. [Security Context A: Client](#client-sec)
    2. [Security Context B: Server](#server-sec)
    3. [Resources](#resources)
3. [Set up the environment](#env-setup)
    1. [Test 0a](#test-0a)
    2. [Test 0b](#test-0b)
4. [Correct OSCORE use](#correct-oscore-use)
    1. [GET test](#get)
        1. [Test 1a](#test-1a)
        2. [Test 1b](#test-1b)
        3. [Test 2a](#test-2a)
        4. [Test 2b](#test-2b)
        5. [Test 3a](#test-3a)
        6. [Test 3b](#test-3b)
        7. [Test 4a](#test-4a)
        8. [Test 4b](#test-4b)
        9. [Test 5a](#test-5a)
        10. [Test 5b](#test-5b)
    2. [POST test](#post)
        1. [Test 6a](#test-6a)
        2. [Test 6b](#test-6b)
    3. [PUT test](#put)       
        1. [Test 7a](#test-7a)
        2. [Test 7b](#test-7b)
        3. [Test 8a](#test-8a)
        4. [Test 8b](#test-8b)
    4. [DELETE test](#del)
        1. [Test 9a](#test-9a)
        2. [Test 9b](#test-9b)
5. [Incorrect OSCORE use](#incorrect-oscore)
    1. [Security Context not matching](#sec-context)
        1. [Test 10a](#test-10a)
        2. [Test 10b](#test-10b)
        3. [Test 11a](#test-11a)
        4. [Test 11b](#test-11b)
        5. [Test 12a](#test-12a)
        6. [Test 12b](#test-12b)
    2. [Replay of a previously sent message](#replay)
        1. [Test 13a](#test-13a)
        2. [Test 13b](#test-13b)
    3. [Accessing a non-OSCORE-protected resource with OSCORE](#auth)
        1. [Test 14a](#test-14a)
        2. [Test 14b](#test-14b)
    4. [Accessing an OSCORE-protected resource without OSCORE](#unauth)
        1. [Test 15a](#test-15a)
        2. [Test 15b](#test-15b)

## 1. Notes

CoAP Version is 1 in all the tests.

The client and server may optionally display external_aad and COSE object (before and after compression) to simplify debugging.

When non-indicated, CoAP messages can be NON or CON (implementer's choice).

To be able to run Test 14, the implementer must run an OSCORE-unaware server.

The number used as Object-Security option number is set to 9 in this document.

## 2. Security Contexts and Resources

### Security Context A: Client {#client-sec}

* Common Context:
    - Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
    - Master Salt: 0x9e7ca92223786340 (8 bytes)
    - Common IV: 0x4622d4dd6d944168eefb54987c (13 bytes)
* Sender Context:
    - Sender ID: 0x (0 byte)
    - Sender Key: 0xf0910ed7295e6ad4b54fc793154302ff (16 bytes)
    - Sender Seq Number: 00
    - Sender IV: 0x4622d4dd6d944168eefb54987c (using Partial IV: 00)
* Recipient Context:
    - Recipient ID: 0x01 (1 byte)
    - Recipient Key: 0xffb14e093c94c9cac9471648b4f98710 (16 bytes)
    - Recipient IV: 0x4722d4dd6d944169eefb54987c (using Partial IV: 00)

### Security Context B: Server {#server-sec}

* Common Context:
    - Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
    - Master Salt: 0x9e7ca92223786340 (8 bytes)
    - Common IV: 0x4622d4dd6d944168eefb54987c (13 bytes)
* Sender Context:
    - Sender Id: 0x01 (1 byte)
    - Sender Key: 0xffb14e093c94c9cac9471648b4f98710 (16 bytes)
    - Sender Seq Number: 00
    - Sender IV: 0x4722d4dd6d944169eefb54987c (using Partial IV: 00)
* Recipient Context:
    - Recipient Id: 0x (0 byte)
    - Recipient Key: 0xf0910ed7295e6ad4b54fc793154302ff (16 bytes)
    - Recipient IV: 0x4622d4dd6d944168eefb54987c (using Partial IV: 00)

### Resources

The list of resources the OSCORE-aware server must implement is the following:

* /oscore/hello/coap : authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)
* /oscore/hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)
* /oscore/hello/2 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain), and with ETag 0x2b
* /oscore/hello/3 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain), and Max-Age 5
* /oscore/hello/6 : protected resource, authorized method: POST, returns the value of the resource with content-format 0 (text/plain)
* /oscore/hello/7 : protected resource, authorized method: PUT, returns the value of the resource with content-format 0 (text/plain), has ETag 0x7b
* /oscore/observe : protected resource, authorized method: GET, supports observe, returns "one" for the first notification, "two" for the second notification. The server is configured to return 5.00 after the 2 notifications are sent.
* /oscore/test: protected resource, authorized method: DEL.

The list of resource the OSCORE-unaware server must implement is the following:

* /oscore/hello/coap : authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

------

## 3. Set up the environment {#env-setup}

### 3.1. Identifier: TEST_0a {#test-0a}

**Objective** : Verify that CoAP exchange works. Perform a simple GET transaction using COAP, Content-Format and Uri-Path option (Client side)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | including:                                               |
|      |          |                                                          |
|      |          | - Uri-Path : /oscore/hello/coap                          |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing expected; expected:                           |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 3.2. Identifier: TEST_0b {#test-0b}

**Objective** : Verify that CoAP exchange works. Perform a simple GET transaction using COAP, Content-Format and Uri-Path option (Server side)

**Configuration** :

_server resources_:

* /oscore/hello/coap : authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | including:                                               |
|      |          |                                                          |
|      |          | - Uri-Path = /oscore/hello/coap                          |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing                                               |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

## 4. Correct OSCORE use

### 4.1 GET Tests {#get}

#### 4.1.1. Identifier: TEST_1a {#test-1a}

**Objective** : Perform a simple GET transaction using OSCORE, Content-Format and Uri-Path option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number received not in client's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a POST request,  |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |       * Code: GET                                        |
|      |          |       * Uri-Path : /oscore/hello/1                       |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 2.05 Content Response with:    |
|      |          |                                                          |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.1.2. Identifier: TEST_1b {#test-1b}

**Objective** : Perform a simple GET transaction using OSCORE, Content-Format and Uri-Path option (Server side)

**Configuration** :

_server security context_: 
[Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* /oscore/hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing; expected: CoAP GET request, including:       |
|      |          |                                                          |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 7    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 2.05 Content Response                        |
|      |          |     * Content-Format = 0 (text/plain)                    |
|      |          |     * Payload = "Hello World!"                           |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 4.1.3. Identifier: TEST_2a {#test-2a}

**Objective** : Perform a GET transaction using OSCORE, Content-Format, Uri-Path, Uri-Query and ETag option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /oscore/hello/2                             |
|      |          | - Uri-Query : first=1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a POST request,  |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: GET                                          |
|      |          |     * Uri-Path : /oscore/hello/2                         |
|      |          |     * Uri-Query : first=1                                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 2.05 Content Response with:    |
|      |          |                                                          |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - ETag with value 0x2b                                   |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+


#### 4.1.4. Identifier: TEST_2b {#test-2b}

**Objective** : Perform a GET transaction using OSCORE, Content-Format, Uri-Path, Uri-Query and ETag option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* /oscore/hello/2 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain), and with ETag 0x2b

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /oscore/hello/2                             |
|      |          | - Uri-Query : first=1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing; expected: CoAP GET request, including:       |
|      |          |                                                          |
|      |          | - Uri-path = /oscore/hello/2                             |
|      |          | - Uri-Query : first=1                                    |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 7    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 2.05 Content Response                        |
|      |          |     * Content-Format = 0 (text/plain)                    |
|      |          |     * ETag with value 0x2b                               |
|      |          |     * Payload = "Hello World!"                           |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 4.1.5. Identifier: TEST_3a {#test-3a}

**Objective** : Perform a GET transaction using OSCORE, Content-Format, Uri-Path, Accept and Max-Age option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /oscore/hello/3                             |
|      |          | - Accept = 0 (text/plain;charset=utf-8)                  |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a POST request,  |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: GET                                          |
|      |          |     * Uri-Path = /oscore/hello/3                         |
|      |          |     * Accept = 0 (text/plain;charset=utf-8)              |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Max-Age with value 0x00                                |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 2.05 Content Response with:    |
|      |          |                                                          |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Max-Age with value 0x05                                |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.1.6. Identifier: TEST_3b {#test-3b}

**Objective** :Perform a GET transaction using OSCORE, Content-Format, Uri-Path, Accept and Max-Age option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* /oscore/hello/3 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain), and Max-Age 5

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /oscore/hello/3                             |
|      |          | - Accept = 0 (text/plain;charset=utf-8)                  |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Max-Age with value 0x00                                |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing; expected: CoAP GET request, including:       |
|      |          |                                                          |
|      |          | - Uri-path = /oscore/hello/3                             |
|      |          | - Accept = 0 (text/plain;charset=utf-8)                  |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 7    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 2.05 Content Response                        |
|      |          |     * Content-Format = 0 (text/plain)                    |
|      |          |     * Max-Age with value 05                              |
|      |          |     * Payload = "Hello World!"                           |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 4.1.7. Identifier: TEST_4a {#test-4a}

**Objective** : Perform a GET transaction using OSCORE, Content-Format, Uri-Path, and Observe. Response without observe. (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /oscore/hello/1                             |
|      |          | - Observe = 0 (Registration)                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a FETCH request, |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: GET                                          |
|      |          |     * Uri-Path = /oscore/hello/1                         |
|      |          |     * Observe = 0 (Registration)                         |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 2.05 Content Response with:    |
|      |          |                                                          |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.1.8. Identifier: TEST_4b {#test-4b}

**Objective** : Perform a GET transaction using OSCORE, Content-Format, Uri-Path, and Observe. Response without observe.  (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* /oscore/hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /oscore/hello/1                             |
|      |          | - Observe = 0 (Registration)                             |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.05 FETCH with:                                         |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing; expected: CoAP GET request, including:       |
|      |          |                                                          |
|      |          | - Uri-path = /oscore/hello/1                             |
|      |          | - Observe = 0 (Registration)                             |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 7    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 2.05 Content Response                        |
|      |          |     * Content-Format = 0 (text/plain)                    |
|      |          |     * Payload = "Hello World!"                           |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 4.1.9. Identifier: TEST_5a {#test-5a}

**Objective** : Perform a GET transaction using OSCORE, Content-Format, Uri-Path, and Observe (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window
* Sequence number received not in client's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /oscore/observe                             |
|      |          | - Observe = 0 (Registration)                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a FETCH request, |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Observe = 0 (Registration)                             |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: GET                                          |
|      |          |     * Uri-Path = /oscore/observe                         |
|      |          |     * Observe = 0 (Registration)                         |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Observe (Notification)                                 |
|      |          | - Object-Security option (with or without Partial IV)    |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 2.05 Content Response with:    |
|      |          |                                                          |
|      |          | - Observe (Notification)                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "one"                                        |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 8    | Check    | Client parses the response; expected:                    |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Observe (Notification)                                 |
|      |          | - Object-Security option (with Partial IV)               |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 9    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 10   | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 2.05 Content Response with:    |
|      |          |                                                          |
|      |          | - Observe (Notification)                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "two"                                        |
+------+----------+----------------------------------------------------------+
| 11   | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 12   | Check    | Client parses the response; expected:                    |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option (with Partial IV)               |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 13   | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 14   | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 5.00 Internal Server Error:    |
|      |          |                                                          |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "Terminate Observe"                          |
+------+----------+----------------------------------------------------------+
| 15   | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.1.10. Identifier: TEST_5b {#test-5b}

**Objective** : Perform a GET transaction using OSCORE, Content-Format, Uri-Path, and Observe (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window
* Sequence sent received not in client's replay window

_server resources_:

* /oscore/observe : protected resource, authorized method: GET, supports observe, returns "one" for the first notification, "two" for the second notification. The server is configured to return 5.00 after the 2 notifications are sent.

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /oscore/observe                             |
|      |          | - Observe = 0 (Registration)                             |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.05 FETCH with:                                         |
|      |          |                                                          |
|      |          | - Observe = 0 (Registration)                             |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing; expected: CoAP GET request, including:       |
|      |          |                                                          |
|      |          | - Uri-path = /oscore/observe                             |
|      |          | - Observe = 0 (Registration)                             |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 7    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Observe (Notification) (with or without Partial IV)    |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 2.05 Content Response                        |
|      |          |     * Content-Format = 0 (text/plain)                    |
|      |          |     * Payload = "one"                                    |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 9    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option (with Partial IV)               |
|      |          | - Observe (Notification)                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 2.05 Content Response                        |
|      |          |     * Content-Format = 0 (text/plain)                    |
|      |          |     * Payload = "two"                                    |
+------+----------+----------------------------------------------------------+
| 10   | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 11   | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option (with Partial IV)               |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 5.00 Internal Server Error                   |
|      |          |     * Content-Format = 0 (text/plain)                    |
|      |          |     * Payload = "Terminate Observe"                      |
+------+----------+----------------------------------------------------------+
| 12   | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

### 4.2. POST Tests {#post}

#### 4.2.1. Identifier: TEST_6a {#test-6a}

**Objective** : Perform a POST transaction using OSCORE, Content-Format, and Uri-Path option, changing a resource (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP POST request      |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /oscore/hello/6                             |
|      |          | - Content-Format = 0                                     |
|      |          | - payload = 0x4a                                         |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a POST request,  |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: POST                                         |
|      |          |     * Uri-Path = /oscore/hello/6                         |
|      |          |     * Content-Format = 0                                 |
|      |          |     * payload = 0x4a                                     |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 2.04 Changed Response with:    |
|      |          |                                                          |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = 0x4a                                         |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.2.2. Identifier: TEST_6b {#test-6b}

**Objective** : Perform a POST transaction using OSCORE, Content-Format, and Uri-Path option, updating a resource (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* /hello/6  : protected resource, authorized method: POST, returns the value of the resource with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP POST request      |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /oscore/hello/6                             |
|      |          | - Content-Format = 0                                     |
|      |          | - payload = 0x4a                                         |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing; expected: CoAP POST request, including:      |
|      |          |                                                          |
|      |          | - Uri-Path = /oscore/hello/6                             |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = 0x4a                                         |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 7    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 2.04 Changed Response                        |
|      |          |     * Content-Format = 0 (text/plain)                    |
|      |          |     * Payload = 0x4a                                     |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

### 4.3 PUT Tests {#PUT}

#### 4.3.1. Identifier: TEST_7a {#test-7a}

**Objective** : Perform a PUT transaction using OSCORE, Uri-Path, Content-Format and If-Match option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /oscore/hello/7                             |
|      |          | - Content-Format = 0                                     |
|      |          | - If-Match with value 0x7b                               |
|      |          | - payload = 0x7a                                         |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a POST request,  |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: PUT                                          |
|      |          |     * Uri-Path = /oscore/hello/7                         |
|      |          |     * Content-Format = 0                                 |
|      |          |     * If-Match with value 0x7b                           |
|      |          |     * payload = 0x7a                                     |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 2.04 Changed Response with:    |
|      |          |                                                          |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = 0x7a                                         |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.3.2. Identifier: TEST_7b {#test-7b}

**Objective** : Perform a PUT transaction using OSCORE, Uri-Path, Content-Format and If-Match option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* /hello/7  : protected resource, authorized method: PUT, returns the value of the resource with content-format 0 (text/plain), has ETag 0x7b

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /oscore/hello/7                             |
|      |          | - Content-Format = 0                                     |
|      |          | - If-Match with value 0x7b                               |
|      |          | - payload = 0x7a                                         |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing; expected: CoAP PUT request, including:       |
|      |          |                                                          |
|      |          | - Uri-Path = /oscore/hello/7                             |
|      |          | - Content-Format = 0                                     |
|      |          | - If-Match with value 0x7b                               |
|      |          | - payload = 0x7a                                         |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 7    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 2.04 Changed Response                        |
|      |          |     * Content-Format = 0 (text/plain)                    |
|      |          |     * Payload 0x7a                                       |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 4.3.3. Identifier: TEST_8a {#test-8a}

**Objective** : Perform a PUT transaction using OSCORE, Uri-Path, Content-Format and If-None-Match option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /oscore/hello/7                             |
|      |          | - Content-Format = 0                                     |
|      |          | - If-None-Match                                          | 
|      |          | - payload = 0x8a                                         |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a POST request,  |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: PUT                                          |
|      |          |     * Uri-Path = /oscore/hello/7                         |
|      |          |     * Content-Format = 0                                 |
|      |          |     * If-None-Match                                      |
|      |          |     * payload = 0x8a                                     |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 4.12 Precondition Failed       |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.3.4. Identifier: TEST_8b {#test-8b}

**Objective** : Perform a PUT transaction using OSCORE, Uri-Path, Content-Format and If-None-Match option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* /oscore/hello/7 : protected resource, authorized method: PUT, returns the value of the resource with content-format 0 (text/plain), has ETag 0x7b

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /oscore/hello/7                             |
|      |          | - Content-Format = 0                                     |
|      |          | - If-None-Match                                          | 
|      |          | - payload = 0x8a                                         |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing; expected: CoAP PUT request, including:       |
|      |          |                                                          |
|      |          | - Uri-Path = /oscore/hello/7                             |
|      |          | - Content-Format = 0                                     |
|      |          | - If-None-Match                                          | 
|      |          | - payload = 0x8a                                         |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 7    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 4.12 Precondition Failed                     |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

### 4.4. DELETE Tests {#DEL}

#### 4.4.1. Identifier: TEST_9a {#test-9a}

**Objective** : Perform a DELETE transaction using OSCORE and Uri-Path option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP DEL request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /oscore/test                                |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a POST request,  |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: DEL                                          |
|      |          |     * Uri-Path = /oscore/test                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 2.02 Deleted                   |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.4.2. Identifier: TEST_9b {#test-9b}

**Objective** : Perform a DELETE transaction using OSCORE and Uri-Path option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* /test: protected resource, authorized method: DEL.

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP DEL request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /oscore/test                                |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing; expected: CoAP DEL request, including:       |
|      |          |                                                          |
|      |          | - Uri-Path = /oscore/test                                |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 7    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 2.02 Deleted                                 |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

## 5. Incorrect OSCORE use {#incorrect-oscore}

### 5.1. Security Context not matching {#sec-context}

#### 5.1.1. Identifier: TEST_10a {#test-10a}

**Objective** : Perform an unauthorized CON GET transaction: non matching Client Sender Id - Server Recipient Id (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender ID: modified sender ID (arbitrarily set by the Client)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option (modified Sender ID)            |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a GET request,   |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: GET                                          |
|      |          |     * Uri-Path = /oscore/hello/1                         |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 4.01 Unauthorized, with:       |
|      |          |                                                          |
|      |          | - Payload: Security context not found (optional)         |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 5.1.2. Identifier: TEST_10b {#test-10b}

**Objective** :Perform an unauthorized GET transaction: non matching Client Sender Id - Server Recipient Id (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec)

_server resources_:

* /oscore/hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option (modified Sender ID)            |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server: OSCORE verification fails (Context not found)    |
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server serialize the response correctly, which is        |
|      |          | 4.01 Unauthorized, with:                                 |
|      |          |                                                          |
|      |          | - Payload: Security context not found (optional)         |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 5.1.3. Identifier: TEST_11a {#test-11a}

**Objective** : Perform a CON GET transaction with non matching Client Sender - Server Recipient Keys (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Key: modified key (arbitrarily set by the Client)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a POST request,  |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: GET                                          |
|      |          |     * Uri-Path = /oscore/hello/1                         |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 4.00 Bad Request error message:|
|      |          |                                                          |
|      |          | - Payload: Decryption failed (optional)                  |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 5.1.4. Identifier: TEST_11b {#test-11b}

**Objective** : Perform a CON GET transaction with non matching Client Sender - Server Recipient Keys (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec)

_server resources_:

* /oscore/hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server: OSCORE verification fails (Decryption failed)    |
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server serialize the response correctly, which is        |
|      |          | 4.00 Bad Request, with:                                  |
|      |          |                                                          |
|      |          | - Payload: Decryption failed (optional)                  |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 5.1.5. Identifier: TEST_12a {#test-12a}

**Objective** : Perform a CON GET transaction with non matching Client Recipient - Server Sender Keys (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Recipient Context:
    - Recipient Key: modified key (arbitrarily set by the Client)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a POST request,  |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: GET                                          |
|      |          |     * Uri-Path = /oscore/hello/1                         |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client: OSCORE verification fails (Decryption failed)    |
|      |          | response dropped, empty ACK sent back to the Server      |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 5.1.6. Identifier: TEST_12b {#test-12b}

**Objective** : Perform a CON GET transaction with non matching Client Recipient - Server Sender Keys (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec)

_server resources_:

* /oscore/hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing; expected: CoAP GET request, including:       |
|      |          |                                                          |
|      |          | - Uri-Path = /oscore/hello/1                              |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 7    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 2.05 Content                                 |
|      |          |     * Content-Format = 0 (text/plain)                    |
|      |          |     * Payload = "Hello World!"                           |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

### 5.2. Replay of a previously sent message {#replay}

#### 5.2.1. Identifier: TEST_13a {#test-13a}

**Objective** : Perform a CON GET transaction using OSCORE, Content-Format and Uri-Path option, request replayed by the Client (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a POST request,  |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: GET                                          |
|      |          |     * Uri-Path = /oscore/hello/1                         |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 2.05 Content Response with:    |
|      |          |                                                          |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 8    | Stimulus | The client is requested to reset its own sequence number |
|      |          | to the value before executing step 1                     |
+------+----------+----------------------------------------------------------+
| 9    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 10   | Check    | Client serializes the request, which is a POST request,  |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: GET                                          |
|      |          |     * Uri-Path = /oscore/hello/1                         |
+------+----------+----------------------------------------------------------+
| 11   | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 12   | Check    | Client parses the response; expected:                    |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 13   | Verify   | Client decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 14   | Check    | Client parses the decrypted response and continues the   |
|      |          | CoAP processing; expected 4.00 Bad Request, with:        |
|      |          |                                                          |
|      |          | - Payload: Replay protection failed (optional)           |
+------+----------+----------------------------------------------------------+
| 15   | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 5.2.2. Identifier: TEST_13b {#test-13b}

**Objective** : Perform a CON GET transaction using OSCORE, Content-Format and Uri-Path option, request replayed by the Client (Client side)

**Configuration** :

_server security context_: [Security Context B](#server-sec)

_server resources_:

* /oscore/hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server decrypts the message: OSCORE verification succeeds|
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing; expected: CoAP GET request, including:       |
|      |          |                                                          |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 7    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: 2.05 Content Response                        |
|      |          |     * Content-Format = 0 (text/plain)                    |
|      |          |     * Payload = "Hello World!"                           |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 8    | Stimulus | The client is requested to reset its own sequence number |
|      |          | to the value before executing step 1                     |
+------+----------+----------------------------------------------------------+
| 9    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Verify   | Server: OSCORE verification fails (Replay protection     |
|      |          | failed)                                                  |
+------+----------+----------------------------------------------------------+
| 5    | Check    | Server serialize the response correctly, which is        |
|      |          | 4.00 Bad Request, with:                                  |
|      |          |                                                          |
|      |          | - Payload: Replay protection failed (optional)           |
+------+----------+----------------------------------------------------------+
| 8    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

### 5.3. Accessing a non-OSCORE-protected resource with OSCORE {#auth}

#### 5.3.1. Identifier: TEST_14a {#test-14a}

**Objective** : Perform a CON GET transaction using OSCORE to an OSCORE-unaware resource server, Content-Format and Uri-Path option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCORE, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /oscore/hello/coap                          |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a POST request,  |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: ciphertext including:                         |
|      |          |     * Code: GET                                          |
|      |          |     * Uri-Path = /oscore/hello/coap                      |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response; expected:                    |
|      |          | 4.02 Bad Option with:                                    |
|      |          |                                                          |
|      |          | - (Optional) Payload                                     |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client: OSCORE verification fails (expected OSCORE)      |
|      |          | response dropped, empty ACK sent back to the             |
+------+----------+----------------------------------------------------------+
| 6    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+


#### 5.3.2. Identifier: TEST_14b {#test-14b}

**Objective** : Perform a CON GET transaction using OSCORE to a non protected resource, Content-Format and Uri-Path option (Server side)

**Configuration** :

The server does not implement OSCORE.

_server security context_: None

_server resources_:

* /oscore/hello/coap : authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request,      |
|      |          | including:                                               |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /oscore/hello/coap                          |
+------+----------+----------------------------------------------------------+
| 2    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 3    | Check    | Server parses the request; expected:                     |
|      |          | 0.02 POST with:                                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload                                                |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 4.02 Bad Option with:                                    |
|      |          |                                                          |
|      |          | - (Optional) Payload                                     |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

### 5.4. Accessing an OSCORE-protected resource without OSCORE {#unauth}

#### 5.4.1. Identifier: TEST_15a {#test-15a}

**Objective** : Perform a CON GET transaction to a protected resource, Content-Format and Uri-Path option (Client side)

**Configuration** :

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request,      |
|      |          | including:                                               |
|      |          |                                                          |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request, which is a GET request,   |
|      |          | with:                                                    |
|      |          |                                                          |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing; expected:                                    |
|      |          | 4.01 Unauthorized error response, with:                  |
|      |          |                                                          |
|      |          | - Payload = diagnostic payload (optional)                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+


#### 5.3.2. Identifier: TEST_15b {#test-15b}

**Objective** : Perform a CON GET transaction to a protected resource, Content-Format and Uri-Path option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec)

_server resources_:

* /oscore/hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request,      |
|      |          | including:                                               |
|      |          |                                                          |
|      |          | - Uri-Path : /oscore/hello/1                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and finds an unrecognized      | 
|      |          | option of class "critical" (the Object-Security option)  |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 4.01 Unauthorized error response, with:                  |
|      |          |                                                          |
|      |          | - Payload = diagnostic payload (optional)                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+
