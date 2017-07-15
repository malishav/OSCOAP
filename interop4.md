# OSCOAP Interop 4 Recap

14-15th of July 2017, all day

## Participants

- Christian Amsüss
- Jim Schaad
- Martin Gunnarsson
- Malisa Vucinic
- Francesca Palombini

## Note takers

Francesca

## Documentation

### \[1\]: [Test specification provided](test-spec3.html)

### \[2\]: [OSCOAP version implemented](https://github.com/core-wg/oscoap/releases/tag/interop-14-07-2017)

## Summary

This 4th interop was carried on before the IETF99. Four implementors participated: Christian, Jim, Martin and Malisa, with implementations based on OSCOAP v-04 (see \[2\]).

The result is summarized in the table below:

+-----------+-----------+-----------+------------------+
|    round  |   Client  |   Server  |       Result     |
+:=========:+:=========:+:=========:+:================:+
| [1](#CMr) | Christian |   Martin  |      Passed      |
+-----------+-----------+-----------+------------------+
| [2](#MlC) |   Malisa  | Christian |      Passed      |
+-----------+-----------+-----------+------------------+
| [3](#MrC) |   Martin  | Christian |      Passed      |
+-----------+-----------+-----------+------------------+
| [4](#CMl) | Christian |   Malisa  |      Passed      |
+-----------+-----------+-----------+------------------+
| [5](#CJ)  | Christian |    Jim    |      Passed      |
+-----------+-----------+-----------+------------------+

The set of tests was run in parallel between most implementations.
The outcome of each test during the run was marked as successful (passed) or not (failed) if the outcome was the one expected according to the test specification \[1\]. Christian has also captured the traffic and shared it with us, to allow for a more extensive analysis of the results.

Test set 5 tests OSCOAP with Blockwise. Jim and Christian did not run Tests 1-15 since they were tested and passed during Interop 3. Also, it is worth noting that all tests marked as \* in Interop 3 were run remotely between Interop 3 and Interop 4 and passed (3, 4, 5).

For test set 2 and 4, many tests were skipped because of features non implemented in the CoAP implementation used, but the OSCOAP processing passed, so the test is considered successful.

In short, this interop for OSCOAP was successful, with some implementations disagreements that provided good feedback and new input for the draft specification.

## Details

## notes:

Added one test: 15: ordinary CoAP request (without OSCOAP) to a resource that requires OSCOAP. Expects 4.01 Unauthorized response.

### 1. Client: Christian, Server: Martin {#CMr}

* 0\. Passed after fixing the server's content format on the response that was not set correctly
* 1\. Passed
* 2\. Passed
* 3\. Passed
* 4\. Passed
* 5\. Invalid AEAD in the response, request sequence number (4.3.2.1. not well iplemented on Christian's side: observe takes the value of the seq)
* 6\. Failed, not enough space to create a resource. When flashed, passed.
* 7\. Passed*
* 8\. Passed*
* 9\. Skipped (Delete not supported)
* 10\. Failed (Token did not match, and error on server's side: finds the context when it should not)
* 11\. Passed*
* 12\. Passed
* 13\. Passed*
* 14\. Skipped
* 15\. Failed (not implemented on Server)

Note: Martin's server sometimes did not send the response back (on Martin's side it looked like it was sent but Christian Client did not receive it)
* CoAP issues in the response.

### 2. Client: Malisa, Server: Christian {#MlC}

* 0\. Passed
* 1\. Passed
* 2\. Skipped (CoAP features not implemented on client)
* 3\. Skipped (CoAP features not implemented on client)
* 4\. Skipped (CoAP features not implemented on client)
* 5\. Skipped (CoAP features not implemented on client)
* 6\. Passed
* 7\. Skipped (CoAP features not implemented on client)
* 8\. Skipped (CoAP features not implemented on client)
* 9\. Skipped (CoAP features not implemented on client)
* 10\. Passed
* 11\. Passed
* 12\. Passed
* 13\. Passed
* 14\. Skipped (CoAP features not implemented on server)
* 15\. Skipped (CoAP features not implemented on client)

Test12: About the "empty ack": the server is sending the response
  piggy-backed, so the client has no reason to send an empty ack back.


### 3. Client: Martin, Server: Christian {#MrC}

* 0\. Passed
* 1\. Passed
* 2\. Passed
* 3\. Passed
* 4\. Skipped
* 5\. Skipped
* 6\. Passed
* 7\. Passed
* 8\. Passed
* 9\. Passed
* 10\. Passed
* 11\. Passed
* 12\. Passed
* 13\. 
* 14\. 
* 15\. 

### 4. Client: Christian, Server: Malisa {#CMl}

* 0\. Passed
* 1\. Passed
* 2\. Skipped (CoAP features not implemented on client)
* 3\. Skipped (CoAP features not implemented on client)
* 4\. Skipped (CoAP features not implemented on client)
* 5\. Skipped (CoAP features not implemented on client)
* 6\. Passed
* 7\. Skipped (CoAP features not implemented on client)
* 8\. Skipped (CoAP features not implemented on client)
* 9\. Skipped (CoAP features not implemented on client)
* 10\. Passed
* 11\. Passed
* 12\. Passed
* 13\. Passed
* 14\. Skipped (CoAP features not implemented on server)
* 15\. Skipped (CoAP features not implemented on client)

What we found that's not tested: CoAP implementations that do not store seen message IDs and the responses (but rather trust that every request is idempotent), like the one under Malisa's OSCOAP implementation, create replay protection errors when a regular CoAP retransmission (eg.
due to a lost response) happens.

Another issue for the "basic CoAP plug tests" list is that tokens are not to be treated like integers, so leading zeros must not be stripped.

### 5. Client: Christian, Server: Jim {#CJ}

* Inner Blockwise tested and passed: client GET to /LargeResource and is served back 5 blocks of size 512 Bytes (tot 2080 Bytes)

## Feedback on Test Specifications and Issues

