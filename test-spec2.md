# Tests Specification for OSCOAP

[//]: # (use Pandoc : pandoc spec.md -o spec.html)

## Table of Contents
1. [Notes](#notes)
2. [Security Contexts and Resources](#security-contexts-and-resources)
    1. [Security Context A: Client](#client-sec)
    2. [Security Context B: Server](#server-sec)
    3. [Resources](#resources)
3. [Correct OSCOAP use](#correct-oscoap-use)
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
4. [Incorrect OSCOAP use](#incorrect-oscoap)
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
    3. [Accessing an OSCOAP-protected resource without OSCOAP](#auth)
        1. [Test 14a](#test-14a)
        2. [Test 14b](#test-14b)

## 1. Notes

CoAP Version is 2 in all the tests.

The client and server may optionally display external_aad and COSE object (before and after compression) to simplify debugging.

When non-indicated, CoAP messages can be NON or CON (implementer's choice)

## 2. Security Contexts and Resources

### Security Context A: Client {#client-sec}

* Common Context:
    - Master Secret: 01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-20-21-22-23
    - Alg: AES-CCM-64-64-128
* Sender Context:
    - Sender Id: 63-6C-69-65-6E-74
    - Sender Key: F8-20-1E-D1-5E-10-37-BC-AF-69-06-07-9A-D3-0B-4F
    - Sender IV: E8-28-A4-79-D0-88-C4
    - Sender Seq Number: 00
* Recipient Context:
    - Recipient Id: 73-65-72-76-65-72
    - Recipient Key: EB-43-09-8A-0F-6F-7B-69-CE-DF-29-E0-80-50-95-82
    - Recipient IV: 58-F9-1A-5C-DF-F4-F5

### Security Context B: Server {#server-sec}

* Common Context:
    - Master Secret: 01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-20-21-22-23
    - Alg: AES-CCM-64-64-128
* Sender Context:
    - Sender Id: 73-65-72-76-65-72
    - Sender Key: EB-43-09-8A-0F-6F-7B-69-CE-DF-29-E0-80-50-95-82
    - Sender IV: 58-F9-1A-5C-DF-F4-F5
    - Sender Seq Number: 00
* Recipient Context:
    - Recipient Id: 63-6C-69-65-6E-74
    - Recipient Key: F8-20-1E-D1-5E-10-37-BC-AF-69-06-07-9A-D3-0B-4F
    - Recipient IV: E8-28-A4-79-D0-88-C4

### Resources

The list of resources the server must implement is the following:

* /hello/coap : authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)
* /hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)
* /hello/2 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain), and with ETag 0x2b
* /hello/3 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain), and Max-Age 5
* /hello/6  : protected resource, authorized method: PUT, returns the value of the resource with content-format 0 (text/plain), has ETag 0x6b
* /observe : protected resource, authorized method: GET, returns a counter incremented every 2 seconds, supports observe.


------

## 3. Set up the environment

### 3.1. Identifier: TEST_0a {#test-0a}

**Objective** : Verify that CoAP exchange works. Perform a simple GET transaction using COAP, Content-Format and Uri-Path option (Client side)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | including:                                               |
|      |          |                                                          |
|      |          | - Uri-Path : /hello/coap                                 |
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

* /hello/coap : authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | including:                                               |
|      |          |                                                          |
|      |          | - Uri-Path = /hello/coap                                 |
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

## 4. Correct OSCOAP use

### 4.1 GET Tests {#get}

#### 4.1.1. Identifier: TEST_1a {#test-1a}

**Objective** : Perform a simple GET transaction using OSCOAP, Content-Format and Uri-Path option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number received not in client's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /hello/1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds); expected:     |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.1.2. Identifier: TEST_1b {#test-1b}

**Objective** : Perform a simple GET transaction using OSCOAP, Content-Format and Uri-Path option (Server side)

**Configuration** :

_server security context_: 
[Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* /hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /hello/1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 3.1.3. Identifier: TEST_2a {#test-2a}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format, Uri-Path, Uri-Query and ETag option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /hello/2                                    |
|      |          | - Uri-Query : first=1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds); expected:     |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - ETag with value 0x2b                                   |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 3.1.4. Identifier: TEST_2b {#test-2b}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format, Uri-Path, Uri-Query and ETag option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* /hello/2 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain), and with ETag 0x2b

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /hello/2                                    |
|      |          | - Uri-Query : first=1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - ETag with value 0x2b                                   |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 3.1.5. Identifier: TEST_3a {#test-3a}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format, Uri-Path, Accept and Max-Age option (Client side)


**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /hello/3                                    |
|      |          | - Accept = 0 (text/plain;charset=utf-8)                  |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds); expected:     |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Max-Age with value 0x05                                |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 3.1.6. Identifier: TEST_3b {#test-3b}

**Objective** :Perform a GET transaction using OSCOAP, Content-Format, Uri-Path, Accept and Max-Age option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* /hello/3 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain), and Max-Age 5

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /hello/3                                    |
|      |          | - Accept = 0 (text/plain;charset=utf-8)                  |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Max-Age with value 0x05                                |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 3.1.7. Identifier: TEST_4a {#test-4a}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format, Uri-Path, and Observe. Response without observe. (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /hello/1                                    |
|      |          | - Observe = 0 (Registration)                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds); expected:     |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload = ...                                          |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+


#### 3.1.8. Identifier: TEST_4b {#test-4b}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format, Uri-Path, and Observe. Response without observe.  (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* * /hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /hello/1                                    |
|      |          | - Observe = 0 (Registration)                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload = ...                                          |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 3.1.9. Identifier: TEST_5a {#test-5a}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format, Uri-Path, and Observe (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window
* Sequence number received not in client's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /observe                                    |
|      |          | - Observe = 0 (Registration)                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds); expected:     |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Observe (Notification)                                 |
|      |          | - Payload = ...                                          |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 6    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds); expected:     |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Observe (Notification)                                 |
|      |          | - Payload = ...                                          |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

Etc.

#### 3.1.10. Identifier: TEST_5b {#test-5b}

**Objective** : Perform a GET transaction using OSCOAP, Content-Format, Uri-Path, and Observe (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window
* Sequence sent received not in client's replay window

_server resources_:

* /observe : protected resource, authorized method: GET, returns a counter incremented every 2 seconds, supports observe.

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-path = /observe                                    |
|      |          | - Observe = 0 (Registration)                             |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Observe (Notification)                                 |
|      |          | - Payload = ...                                          |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 6    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Observe (Notification)                                 |
|      |          | - Payload = ...                                          |
+------+----------+----------------------------------------------------------+
| 7    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

Etc.

### 3.2. POST Tests {#post}

#### 3.2.1. Identifier: TEST_6a {#test-6a}

**Objective** : Perform a POST transaction using OSCOAP, Content-Format, Location-path, Location-Query and Uri-Path option, creating a resource (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP POST request      |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /hello/6                                    |
|      |          | - Content-Format = 0                                     |
|      |          | - payload = 0x4a                                         |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds); expected:     |
|      |          | 2.01 Created Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Location-path = /hello/6                               |
|      |          | - Location-Query : first=1                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 3.2.2. Identifier: TEST_6b {#test-6b}

**Objective** : Perform a POST transaction using OSCOAP, Content-Format, Location-path, Location-Query and Uri-Path option, creating a resource (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:


**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP POST request      |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /hello/6                                    |
|      |          | - Content-Format = 0                                     |
|      |          | - payload = 0x4a                                         |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.01 Created Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Location-path = /hello/6                               |
|      |          | - Location-Query : first=1                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

### 3.3 PUT Tests {#PUT}

#### 3.3.1. Identifier: TEST_7a {#test-7a}

**Objective** : Perform a PUT transaction using OSCOAP, Uri-Path, Content-Format and If-Match option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /hello/7                                    |
|      |          | - Content-Format = 0                                     |
|      |          | - If-Match with value 0x7b                               |
|      |          | - payload = 0x7a                                         |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds); expected:     |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 3.3.2. Identifier: TEST_7b {#test-7b}

**Objective** : Perform a PUT transaction using OSCOAP, Uri-Path, Content-Format and If-Match option (Server side)

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
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /hello/7                                    |
|      |          | - Content-Format = 0                                     |
|      |          | - If-Match with value 0x7b                               |
|      |          | - payload = 0x7a                                         |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.04 Changed Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 3.3.3. Identifier: TEST_8a {#test-8a}

**Objective** : Perform a PUT transaction using OSCOAP, Uri-Path, Content-Format and If-None-Match option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /hello/7                                    |
|      |          | - Content-Format = 0                                     |
|      |          | - If-None-Match                                          | 
|      |          | - payload = 0x7a                                         |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds); expected:     |
|      |          | 4.12 Precondition Failed Response with:                  |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 3.3.4. Identifier: TEST_8b {#test-8b}

**Objective** : Perform a PUT transaction using OSCOAP, Uri-Path, Content-Format and If-None-Match option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:

* /hello/7 : protected resource, authorized method: PUT, returns the value of the resource with content-format 0 (text/plain), has ETag 0x7b

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP PUT request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /hello/7                                    |
|      |          | - Content-Format = 0                                     |
|      |          | - If-None-Match                                          | 
|      |          | - payload = 0x8a                                         |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 4.12 Precondition Failed Response with:                  |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

### 3.4. DELETE Tests {#DEL}

#### 3.4.1. Identifier: TEST_9a {#test-9a}

**Objective** : Perform a DELETE transaction using OSCOAP and Uri-Path option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec), with:

* Sequence number sent not in server's replay window

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP DEL request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /test                                       |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds); expected:     |
|      |          | 2.02 Deleted Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 3.4.2. Identifier: TEST_9b {#test-9b}

**Objective** : Perform a DELETE transaction using OSCOAP and Uri-Path option (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec), with:

* Sequence number received not in server's replay window

_server resources_:



**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP DEL request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path = /test                                       |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.02 Deleted Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

## 4. Incorrect OSCOAP use {#incorrect-oscoap}

### 4.1. Security Context not matching {#sec-context}

#### 4.1.1. Identifier: TEST_10a {#test-10a}

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
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option (modified Sender ID)            |
|      |          | - Uri-Path : /hello/1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response :                             |
|      |          | OSCOAP verification succeeds; expected response:         |
|      |          | 4.01 Unauthorized error message:                         |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: Security context not found (optional)         |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.1.2. Identifier: TEST_10b {#test-10b}

**Objective** :Perform an unauthorized GET transaction: non matching Client Sender Id - Server Recipient Id (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec)

_server resources_:

* /hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option (modified Sender ID)            |
|      |          | - Uri-Path : /hello/1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | The message verification [7.2] fails and the server      |
|      |          | sends an error back (stop CoAP processing)               |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 4.01 Unauthorized error message:                         |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: Security context not found (optional)         |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 4.1.3. Identifier: TEST_11a {#test-11a}

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
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /hello/1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response :                             |
|      |          | OSCOAP verification succeeds; expected response:         |
|      |          | 4.00 Bad Request error message:                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: Decryption failed (optional)                  |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.1.4. Identifier: TEST_11b {#test-11b}

**Objective** : Perform a CON GET transaction with non matching Client Sender - Server Recipient Keys (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec)

_server resources_:

* /hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /hello/1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | The message verification [7.2] fails and the server      |
|      |          | sends an error back (stop CoAP processing)               |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 4.00 Bad Request error message:                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload: Decryption failed (optional)                  |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

#### 4.1.5. Identifier: TEST_12a {#test-12a}

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
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /hello/1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response :                             |
|      |          | OSCOAP verification failure [7.4]; response dropped      |
|      |          | empty ACK sent back to the server                        |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.1.6. Identifier: TEST_12b {#test-12b}

**Objective** : Perform a CON GET transaction with non matching Client Recipient - Server Sender Keys (Server side)

**Configuration** :

_server security context_: [Security Context B](#server-sec)

_server resources_:

* /hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /hello/1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

### 4.2. Replay of a previously sent message {#replay}

#### 4.2.1. Identifier: TEST_13a {#test-13a}

**Objective** : Perform a CON GET transaction using OSCOAP, Content-Format and Uri-Path option, request replayed by the Client (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /hello/1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds); expected:     |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 6    | Stimulus | The client is requested to reset its own sequence number |
|      |          | to the value before executing step 1                     |
+------+----------+----------------------------------------------------------+
| 7    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /hello/1                                    |
+------+----------+----------------------------------------------------------+
| 8    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 9    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 10   | Check    | Client parses the response and continues the CoAP        |
|      |          | processing (OSCOAP verification succeeds); expected:     |
|      |          | 4.00 Bad Request error message:                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload = Replay protection failed (optional)          |
+------+----------+----------------------------------------------------------+
| 11   | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+

#### 4.2.2. Identifier: TEST_13b {#test-13b}

**Objective** : Perform a CON GET transaction using OSCOAP, Content-Format and Uri-Path option, request replayed by the Client (Client side)

**Configuration** :

_server security context_: [Security Context B](#server-sec)

_server resources_:

* /hello/1 : protected resource, authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /hello/1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and continues the CoAP         |
|      |          | processing (OSCOAP verification succeeds)                |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 2.05 Content Response with:                              |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Content-Format = 0 (text/plain)                        |
|      |          | - Payload = "Hello World!"                               |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 6    | Stimulus | The client is requested to reset its own sequence number |
|      |          | to the value before executing step 1                     |
+------+----------+----------------------------------------------------------+
| 7    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /hello/1                                    |
+------+----------+----------------------------------------------------------+
| 2    | Check    | The message verification [6.2] fails and the server      |
|      |          | sends an error back (stop CoAP processing)               |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 4.00 Bad Request error message:                          |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Payload = Replay protection failed (optional)          |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+

### 4.3. Accessing a non-OSCOAP-protected resource with OSCOAP {#auth}

#### 4.3.1. Identifier: TEST_14a {#test-14a}

**Objective** : Perform a CON GET transaction using OSCOAP to a non protected resource, Content-Format and Uri-Path option (Client side)

**Configuration** :

_client security context_: [Security Context A](#client-sec)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request       |
|      |          | protected with OSCOAP, including:                        |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /hello/coap                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Client serializes the request                            |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Client displays the sent packet                          |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Client parses the response :                             |
|      |          | OSCOAP verification failure [7.4]; response dropped      |
|      |          | empty ACK sent back to the server                        |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Client displays the received packet                      |
+------+----------+----------------------------------------------------------+


#### 4.3.2. Identifier: TEST_14b {#test-14b}

**Objective** : Perform a CON GET transaction using OSCOAP to a non protected resource, Content-Format and Uri-Path option (Server side)

**Configuration** :

The server does not implement OSCOAP.

_server security context_: None

_server resources_:

* /hello/coap : authorized method: GET, returns the string "Hello World!" with content-format 0 (text/plain)

**Test Sequence**

+------+----------+----------------------------------------------------------+
| Step | Type     | Description                                              |
+======+==========+==========================================================+
| 1    | Stimulus | The client is requested to send a CoAP GET request,      |
|      |          | including:                                               |
|      |          |                                                          |
|      |          | - Object-Security option                                 |
|      |          | - Uri-Path : /hello/coap                                 |
+------+----------+----------------------------------------------------------+
| 2    | Check    | Server parses the request and finds an unrecognized      | 
|      |          | option of class "critical" (the object-security option)  |
+------+----------+----------------------------------------------------------+
| 3    | Verify   | Server displays the received packet                      |
+------+----------+----------------------------------------------------------+
| 4    | Check    | Server serialize the response correctly, which is:       |
|      |          | 4.02 Bad Option error response, with:                    |
|      |          |                                                          |
|      |          | - Payload = diagnostic payload (optional)                |
+------+----------+----------------------------------------------------------+
| 5    | Verify   | Server displays the sent packet                          |
+------+----------+----------------------------------------------------------+
