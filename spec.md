# Tests Specification for OSCOAP

[//]: # (use Pandoc : pandoc spec.md -o spec.html)

## Table of Contents
1. [Notes](#notes)
2. [Security Contexts](#security-contexts)
    1. [Security Context A: Client](#client-sec)
    2. [Security Context B: Server](#server-sec)
3. [Correct OSCOAP use](#correct-oscoap-use)
    1. [GET test](#get)
        1. [Test 1a](#test-1a)
        2. [Test 1b](#test-1b)
        3. [Test 2a](#test-2a)
        4. [Test 2b](#test-2b)
        5. [Test 3a](#test-3a)
        6. [Test 3b](#test-3b)
    2. [POST test](#pot)
        1. [Test 4a](#test-4a)
        2. [Test 4b](#test-4b)
    3. [PUT test](#put)
        1. [Test 5a](#test-5a)
        2. [Test 5b](#test-5b)
    4. [DELETE test](#del)
        1. [Test 6a](#test-6a)
        2. [Test 6b](#test-6b)
    5. [CoAP Error](#coap-error)
        1. [Test 7a](#test-7a)
        2. [Test 7b](#test-7b)
4. [Incorrect OSCOAP use](#incorrect-oscoap)
    1. [Security Context not matching](#sec-context)
        1. [TEST_8a](#test-8a)
        2. [TEST_8b](#test-8b)
        3. [TEST_9a](#test-9a)
        4. [TEST_9b](#test-9b)
        5. [TEST_10a](#test-10a)
        6. [TEST_10b](#test-10b)
        7. [TEST_11a](#test-11a)
        2. [TEST_11b](#test-11b)
        3. [TEST_12a](#test-12a)
        4. [TEST_12b](#test-12b)
        5. [TEST_13a](#test-13a)
        6. [TEST_13b](#test-13b)
    2. [Replay of a previously sent message](#replay)
        1. [TEST_14a](#test-14a)
        2. [TEST_14b](#test-14b)
        3. [TEST_15a](#test-15a)
        4. [TEST_15b](#test-15b)
        5. [TEST_16a](#test-16a)
        6. [TEST_16b](#test-16b)
    3. [Accessing an OSCOAP-protected resource without OSCOAP](#unauth)
        1. [TEST_17a](#test-17a)
        2. [TEST_17b](#test-17b)

## 1. Notes

CoAP Version is 1 in all the tests.

At the current state of these test specifications, the Base Key is not used.

## 2. Security Contexts

### Security Context A: Client {#client-sec}

* Common Context:
    - Base Key: 01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-20-21-22-23
    - Alg: AES-CCM-64-64-128
    - Context Id: 4B-65-79-23-30
* Sender Context:
    - Sender Id: 63-6C-69-65-6E-74
    - Sender Key: F8-20-1E-D1-5E-10-37-BC-AF-69-06-07-9A-D3-0B-4F
    - Sender IV: E8-28-A4-79-D0-88-C4
    - Sender Seq Number: 00
* Recipient Context:
    - Recipient Id: 73-65-72-76-65-72
    - Recipient Key: EB-43-09-8A-0F-6F-7B-69-CE-DF-29-E0-80-50-95-82
    - Recipient IV: 58-F9-1A-5C-DF-F4-F5
    - Recipient Seq Number: 00

### Security Context B: Server {#server-sec}

* Common Context:
    - Base Key: 01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-20-21-22-23
    - Alg: AES-CCM-64-64-128
    - Context Id: 4B-65-79-23-30
* Sender Context:
    - Sender Id: 73-65-72-76-65-72
    - Sender Key: EB-43-09-8A-0F-6F-7B-69-CE-DF-29-E0-80-50-95-82
    - Sender IV: 58-F9-1A-5C-DF-F4-F5
    - Sender Seq Number: 00
* Recipient Context:
    - Recipient Id: 63-6C-69-65-6E-74
    - Recipient Key: F8-20-1E-D1-5E-10-37-BC-AF-69-06-07-9A-D3-0B-4F
    - Recipient IV: E8-28-A4-79-D0-88-C4
    - Recipient Seq Number: 00

------

## 3. Correct OSCOAP use

### 3.1 GET Tests {#get}

#### 3.1.1. Identifier: TEST_1a {#test-1a}

**Objective** : Perform a simple GET transaction using OSCOAP, Content-Format and Uri-Path option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: 01
* Recipient Context:
    - Recipient Seq Number: 01

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Client displays the received packet                    |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 3.1.2. Identifier: TEST_1b {#test-1b}

**Objective** : Perform a simple GET transaction using OSCOAP, Content-Format and Uri-Path option (Server side)

**Configuration** :

_server security context_: 
[Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 01
* Recipient Context:
    - Recipient Seq Number: 01

_server resources_:

* /helloworld : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, including:      |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Server displays the sent packet                        |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+

#### 3.1.3. Identifier: TEST_2a {#test-2a}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format, Uri-Path, Uri-Query and ETag option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: 02
* Recipient Context:
    - Recipient Seq Number: 02


**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /helloworld                                 |
|      |          | - Uri-Query : first=1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Client displays the received packet                    |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 3.1.4. Identifier: TEST_2b {#test-2b}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format, Uri-Path, Uri-Query and ETag option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 02
* Recipient Context:
    - Recipient Seq Number: 02

_server resources_:

* /helloworld : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain), and with ETag 0x2b

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /helloworld                                 |
|      |          | - Uri-Query : first=1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, including       |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - ETag with value 0x2b                                   |
|      |          | - payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Server displays the sent packet                        |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+

#### 3.1.5. Identifier: TEST_3a {#test-3a}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format, Uri-Path, Uri-Query, ETag, Accept and Max-Age option (Client side)


**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: 03
* Recipient Context:
    - Recipient Seq Number: 03

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /helloworld                                 |
|      |          | - Uri-Query : second=2                                   |
|      |          | - Accept = 0 (text/plain;charset=utf-8)                  |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Client displays the received packet                    |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 3.1.6. Identifier: TEST_3b {#test-3b}

**Objective** :Perform a GET transaction using OSCOAP, Content-Format, Uri-Path, Uri-Query, ETag, Accept and Max-Age option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 03
* Recipient Context:
    - Recipient Seq Number: 03

_server resources_:

* /helloworld : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain), with ETag 0x2b and Max-Age 5

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /helloworld                                 |
|      |          | - Uri-Query : second=2                                   |
|      |          | - Accept = 0 (text/plain;charset=utf-8)                  |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, including       |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - ETag with value 0x2b                                   |
|      |          | - Max-Age with value 0x05                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Server displays the sent packet                        |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+

### 3.2. POST Tests {#post}

#### 3.2.1. Identifier: TEST_4a {#test-4a}

**Objective** : Perform a POST transaction using OSCOAP, Content-Format, Location-path, Location-Query and Uri-Path option, creating a resource (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: 04
* Recipient Context:
    - Recipient Seq Number: 04

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP POST request      |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /counter                                    |
|      |          | - Content-Format = 0                                     |
|      |          | - payload = 4a4a4a4a                                     |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Client displays the received packet                    |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 3.2.2. Identifier: TEST_4b {#test-4b}

**Objective** : Perform a POST transaction using OSCOAP, Content-Format, Location-path, Location-Query and Uri-Path option, creating a resource (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 04
* Recipient Context:
    - Recipient Seq Number: 04

_server resources_:


**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP POST request      |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /counter                                    |
|      |          | - Content-Format = 0                                     |
|      |          | - payload = 4a4a4a4a                                     |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, including       |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Location-path = /counter                               |
|      |          | - Location-Query : first=1                               |
|      |          | - Location-Query : second=2                              |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Server displays the sent packet                        |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+

### 3.3 PUT Tests {#PUT}

#### 3.3.1. Identifier: TEST_5a {#test-5a}

**Objective** : Perform a PUT transaction using OSCOAP, Uri-Path and If-Match option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: 05
* Recipient Context:
    - Recipient Seq Number: 05

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /counter                                    |
|      |          | - Content-Format = 0                                     |
|      |          | - If-Match with value 0x5b5b                             |
|      |          | - payload = 5a5a5a5a                                     |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Client displays the received packet                    |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 3.3.2. Identifier: TEST_5b {#test-5b}

**Objective** : Perform a PUT transaction using OSCOAP, Uri-Path and If-Match option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 05
* Recipient Context:
    - Recipient Seq Number: 05

_server resources_:

* /counter  : protected resource, authorized method: PUT, returns the value of the counter with content-format 0 (text/plain), has ETag 0x5b5b

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /counter                                    |
|      |          | - Content-Format = 0                                     |
|      |          | - If-Match with value 0x5b5b                             |
|      |          | - payload = 5a5a5a5a                                     |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, including       |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Server displays the sent packet                        |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+

### 3.4. DELETE Tests {#DEL}

#### 3.4.1. Identifier: TEST_6a {#test-6a}

**Objective** : Perform a DELETE transaction using OSCOAP and Uri-Path option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: 06
* Recipient Context:
    - Recipient Seq Number: 06

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /counter                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Client displays the received packet                    |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 3.4.2. Identifier: TEST_6b {#test-6b}

**Objective** : Perform a DELETE transaction using OSCOAP and Uri-Path option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 06
* Recipient Context:
    - Recipient Seq Number: 06

_server resources_:

* /counter  : protected resource, authorized method: DEL

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /counter                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly                  |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Server displays the sent packet                        |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+

## 3.5. CoAP Error {#coap-error}

#### 3.5.1. Identifier: TEST_7a {#test-7a}

**Objective** : Perform a DELETE transaction on an non-existing resource using OSCOAP and Uri-Path option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: 07
* Recipient Context:
    - Recipient Seq Number: 07

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /error                                      |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Client displays the received packet                    |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 3.5.2. Identifier: TEST_7b {#test-7b}

**Objective** : Perform a DELETE transaction on an non-existing resource using OSCOAP and Uri-Path option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 07
* Recipient Context:
    - Recipient Seq Number: 07

_server resources_:


**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /error                                      |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the error 4.04 response correctly       |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - payload (error message)                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Server displays the sent packet                        |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+

--------------

## 4. Incorrect OSCOAP use {#incorrect-oscoap}

### 4.1. Security Context not matching {#sec-context}

#### 4.1.1. Identifier: TEST_8a {#test-8a}

**Objective** : Perform a GET transaction with non matching Client Sender - Server Recipient Keys (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Key: **11**-20-1E-D1-5E-10-37-BC-AF-69-06-07-9A-D3-0B-4F
    - Sender Seq Number: 08
* Recipient Context:
    - Recipient Seq Number: 08

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client doesn't receive a response back                   |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet (if any)             |
+------+----------+----------------------------------------------------------+

#### 4.1.2. Identifier: TEST_8b {#test-8b}

**Objective** : Perform a GET transaction with non matching Client Sender - Server Recipient Keys (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 08
* Recipient Context:
    - Recipient Seq Number: 08

_server resources_:

* /helloworld : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | The message verification [6.3] fails and the server      |
|      |          | stops processing the message                             |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 4.1.3.Identifier: TEST_9a {#test-9a}

**Objective** : Perform a GET transaction with non matching Client Sender - Server Recipient IVs(Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender IV: **11**-28-A4-79-D0-88-C4
    - Sender Seq Number: 09
* Recipient Context:
    - Recipient Seq Number: 09

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client doesn't receive a response back                   |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet (if any)             |
+------+----------+----------------------------------------------------------+

#### 4.1.4. Identifier: TEST_9b {#test-9b}

**Objective** : Perform a GET transaction with non matching Client Sender - Server Recipient Keys (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 09
* Recipient Context:
    - Recipient Seq Number: 09

_server resources_:

* /helloworld : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | The message verification [6.3] fails and the server      |
|      |          | stops processing the message                             |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 4.1.5. Identifier: TEST_10a {#test-10a}

**Objective** : Perform a GET transaction with non matching Client Sender - Server Recipient Ids(Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Id: **11**-6C-69-65-6E-74
    - Sender Seq Number: 0A
* Recipient Context:
    - Recipient Seq Number: 0A

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client doesn't receive a response back                   |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet (if any)             |
+------+----------+----------------------------------------------------------+

#### 4.1.6 Identifier: TEST_10b {#test-10b}

**Objective** : Perform a GET transaction with non matching Client Sender - Server Recipient Keys (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 0A
* Recipient Context:
    - Recipient Seq Number: 0A

_server resources_:

* /helloworld : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | The message verification [6.3] fails and the server      |
|      |          | stops processing the message                             |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 4.1.7. Identifier: TEST_11a {#test-11a}

**Objective** : Perform a GET transaction with non matching Client Recipient - Server Sender Keys (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: 0B
* Recipient Context:
    - Recipient Key: **11**-43-09-8A-0F-6F-7B-69-CE-DF-29-E0-80-50-95-82
    - Recipient Seq Number: 0B

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | The message verification [6.5] fails and the client      |
|      |          | stops processing the message                             |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Client displays the received packet                    |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 4.1.8. Identifier: TEST_11b {#test-11b}

**Objective** : Perform a GET transaction with non matching Client Recipient - Server Sender Keys (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 0B
* Recipient Context:
    - Recipient Seq Number: 0B

_server resources_:

* /helloworld : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, including:      |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Server displays the sent packet                        |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+

#### 4.1.9. Identifier: TEST_12a {#test-12a}

**Objective** : Perform a GET transaction with non matching Client Recipient - Server Sender IVs (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: 0C
* Recipient Context:
    - Recipient IV: **11**-F9-1A-5C-DF-F4-F5
    - Recipient Seq Number: 0C

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | The message verification [6.5] fails and the client      |
|      |          | stops processing the message                             |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Client displays the received packet                    |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 4.1.10. Identifier: TEST_12b {#test-12b}

**Objective** : Perform a GET transaction with non matching Client Recipient - Server Sender IVs (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 0C
* Recipient Context:
    - Recipient Seq Number: 0C

_server resources_:

* /helloworld : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, including:      |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Server displays the sent packet                        |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+

#### 4.1.11. Identifier: TEST_13a {#test-13a}

**Objective** : Perform a GET transaction with non matching Client Recipient - Server Sender Ids (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: 0D
* Recipient Context:
    - Recipient Id: **11**-65-72-76-65-72
    - Recipient Seq Number: 0D

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | The message verification [6.5] fails and the client      |
|      |          | stops processing the message                             |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Client displays the received packet                    |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 4.1.12. Identifier: TEST_13b {#test-13b}

**Objective** : Perform a GET transaction with non matching Client Recipient - Server Sender Ids (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 0D
* Recipient Context:
    - Recipient Seq Number: 0D

_server resources_:

* /helloworld : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, including:      |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Server displays the sent packet                        |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+


### 4.2. Replay of a previously sent message {#replay}

#### 4.2.1. Identifier: TEST_14a {#test-14a}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format and Uri-Path option, request replayed by the Client (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: **00**
* Recipient Context:
    - Recipient Seq Number: 0E

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the sequence number in the  |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client doesn't receive a response back                   |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet (if any)             |
+------+----------+----------------------------------------------------------+

#### 4.2.2. Identifier: TEST_14b {#test-14b}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format and Uri-Path option, request replayed by the Client (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 0E
* Recipient Context:
    - Recipient Seq Number: **65**

_server resources_:

* /helloworld : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | The message verification [6.3] fails and the server      |
|      |          | stops processing the message                             |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the sequence number in the  |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 4.2.3. Identifier: TEST_15a {#test-15a}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format and Uri-Path option, response replayed by the Server (Correct Tid) (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: 0F
* Recipient Context:
    - Recipient Seq Number: **65**

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | The message verification [6.5] fails and the client      |
|      |          | stops processing the message                             |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Client displays the received packet                    |
|      |          | - (Optional) Client displays the sequence number in the  |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 4.2.4. Identifier: TEST_15b {#test-15b}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format and Uri-Path option, response replayed by the Server (Correct Tid) (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: **00**
* Recipient Context:
    - Recipient Seq Number: 0F

_server resources_:

* /helloworld : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, including:      |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Server displays the sent packet                        |
|      |          | - (Optional) Server displays the sequence number in the  |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+

#### 4.2.5. Identifier: TEST_16a {#test-16a}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format and Uri-Path option, response replayed by the Server (Wrong Tid) (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sender Context:
    - Sender Seq Number: **10**
* Recipient Context:
    - Recipient Seq Number: 10

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /change-tid                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Client displays the sent packet                        |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+
| 4    | Check    | The message verification [6.5] fails and the client      |
|      |          | stops processing the message                             |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Client displays the received packet                    |
|      |          | - (Optional) Client displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Client displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+

#### 4.2.6. Identifier: TEST_16b {#test-16b}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format and Uri-Path option, response replayed by the Server (Wrong Tid) (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 10
* Recipient Context:
    - Recipient Seq Number: 10

_server resources_:

* /change-tid : protected resource, authorized method: GET, modify the Tid of the response to an arbitrary value, returns the string "Hello World!" with content-format 0 (text/plain) 

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /change-tid                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | - Server displays the received packet                    |
|      |          | - (Optional) Server displays the Tid for the received    |
|      |          | message                                                  |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | received message                                         |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | received message                                         |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, including:      |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - payload                                                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | - Server displays the sent packet                        |
|      |          | - (Optional) Server displays the external_aad for the    |
|      |          | sent message                                             |
|      |          | - (Optional) Server displays the COSE object for the     |
|      |          | sent message                                             |
+------+----------+----------------------------------------------------------+

### 4.3. Accessing an OSCOAP-protected resource without OSCOAP {#unauth}

#### 4.3.1. Identifier: TEST_17a {#test-17a}

**Objective** : Perform a GET transaction without using OSCOAP to a protected resource, Content-Format and Uri-Path option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

N/A

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request,      |
|      |          | including:                                               |
|      |          |                                                          |
|      |          | - Uri-Path : /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.3.2. Identifier: TEST_17b {#test-17b}

**Objective** : Perform a GET transaction without using OSCOAP to a protected resource, Content-Format and Uri-Path option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sender Context:
    - Sender Seq Number: 11
* Recipient Context:
    - Recipient Seq Number: 11

_server resources_:

* /helloworld : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request,      |
|      |          | including:                                               |
|      |          |                                                          |
|      |          | - Uri-Path : /helloworld                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | The message verification [6.3] fails                     |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, including:      |
|      |          |                                                          |
|      |          | - Error code 4.01 Unauthorized                           |
|      |          | - (Optional) Content-Format = 0 (text/plain)             |
|      |          | - (Optional) payload                                     |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+
