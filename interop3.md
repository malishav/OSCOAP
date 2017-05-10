# OSCOAP Interop 3 Recap

8th of March 2017, 13:30-17:00 CET

## Participants

- Christian Amsüss
- Jim Schaad
- Martin Gunnarsson
- Tobias Andersson
- Göran Selander
- Francesca Palombini

## Note takers

Francesca, Christian

## Documentation

### \[1\]: [Test specification provided](test-spec2.html)

### \[2\]: [OSCOAP version implemented](https://github.com/core-wg/oscoap/releases/tag/interop-08-05-2017)

## Summary

This 3rd interop was carried on after the IETF98. Four implementors participated: Christian, Jim, Martin and Tobias, with implementations based on OSCOAP v-03 (see \[2\]).

Jim and Christian implemented both server and client, while Martin only implemented a server and Tobias only a client.

The result is summarized in the table below:

+-----------+-----------+-----------+------------------+
|    round  |   Client  |   Server  |       Result     |
+:=========:+:=========:+:=========:+:================:+
| [1](#TJ)  |   Tobias  |    Jim    |      Passed      |
+-----------+-----------+-----------+------------------+
| [2](#CJ)  | Christian |    Jim    |      Passed      |
+-----------+-----------+-----------+------------------+
| [3*](#CM) | Christian |   Martin  | Connection error |
+-----------+-----------+-----------+------------------+
| [4*](#JM) |    Jim    |   Martin  | Connection error |
+-----------+-----------+-----------+------------------+
| [5*](#TC) |   Tobias  | Christian |      Failed      |
+-----------+-----------+-----------+------------------+
| [6](#JC)  |    Jim    | Christian |      Passed      |
+-----------+-----------+-----------+------------------+

\* To be continued

Martin's implementation had network issues. Test 5 could not be fixed by lack of time, so it stopped at the detection of the error.

The set of tests was run in parallel between most implementations.
The outcome of each test during the run was marked as successful (passed) or not (failed) if the outcome was the one expected according to the test specification \[1\]. Christian and Jim have also captured the traffic and shared it with us, to allow for a more extensive analysis of the results.

In short, the interop for OSCOAP was mostly successful, with some implementations disagreements that provided good feedback and new input for the draft specification.

## Details

## notes:

(**) Test 12 is only correctly described for scenarios where the response is not piggibacked on the ACK. If that's the case, the client is not requested to send an ACK back in case of error.

Added one test: 15: ordinary CoAP request (without OSCOAP) to a resource that requires OSCOAP. Expects 4.01 Unauthorized response.

### 1. Client: Tobias', Server: Jim's {#TJ}

* 0\. Initially didn't pass for an error on the request URI used by the client (client did not receive any response), then created an error "Bad request" on the server side because of implementation error on server's side. After correction on client and server, passed
* 1\. Initially failed with "decryption failed" error for the response on the client side. The problem was an implementation mistake from the server, which did not send the first byte in the response (since it has value 0x0 for response without observe). After correction, passed.
* 2\. Passed
* 3\. Initially failed because of wrong request URI used by the client (client did not receive any response), after correction passed
* 4\. Passed
* 5\. Initially failed because of wrong request URI used by the client (client did not receive any response); after correction the client only got 1 response from the server with an observe option empty.
* 6\. Passed
* 7\. Initially failed (client received the wrong CoAP response) because of implementation error on server's etag value. After correction passed
* 8\. Passed
* 9\. Failed since the client did not implement the test correctly
* 10\. Passed
* 11\. Passed
* 12\. Passed (**)
* 13\. Passed (after server turned on replay protection)
* 14\. Not tested (not possible to implement on server's side)
* 15\. Passed

### 2. Client: Christian's, Server: Jim's {#CJ}

* 0\. Passed
* 1\. Passed
* 2\. Passed
* 3\. Passed
* 4\. Initially failed: the request decryption failed on server's side. The error was an implementation error in the aad: empty observe option. After correction, passed
* 5\. Initially failed not sending observe, server is looking for inside observe. Fixed on Christian's side according to -03 4.3.2.1. Then failed because of the disagreement about flipped request-sequno used for the first response with observe (Christian understanding) vs uses its own sequence number even for the first response with observe (Jim's understanding) 
* 6\. Passed with Location-Path is /hello/ instead of /hello/6 (test spec error) 
* 7\. Passed
* 8\. Passed
* 9\. Passed
* 10\. Passed
* 11\. Passed
* 12\. Passed
* 13\. Passed (after server turned on replay protection)
* 14\. Not tested (not possible to implement on server's side)
* 15\. Passed

### 3. Client: Christian's, Server: Martin's {#CM}

* 0\. Passed
* 1\. and following failed: initially failed for decryption error on server's side (server's implementation error: sender id used was wrong). After correction, responses do not get through but errors from retransmissions do.

### 4. Client: Jim's, Server: Martin's {#JM}

* 0\. Passed
* 1\. and following failed: responses do not get through but errors from retransmissions do.

### 5. Client: Tobias', Server: Christian's {#TC}

* 0\. Passed
* 1\. Passed on client side, fails on server's side: the server detects an inner object-security option in the request that should not be there (implementation error on client's side)
* 2-4\. Same as above
* 5\. Passed for first response, but the second response triggered a client error in unpacking the compressed data; later failed due to disagreement whether the initial response can be a first-bit-flipped response to the original request or not (same problem as client:Christian-server:Jim for test 5)

### 6. Client: Jim's, Server: Christian's {#JC}

* 0\. Passed
* 1\. Passed
* 2\. Passed
* 3\. Passed
* 4\. Initially failed because client used the wrong URI. After correction, passed
* 5\. Skipped because of the disagreement about flipped request-sequno used for the first response with observe (Christian understanding) vs uses its own sequence number even for the first response with observe (Jim's understanding) 
* 6\. Passed
* 7\. Passed (Content-Format:0 option missing)
* 8\. Passed 
* 9\. Passed
* 10\. Passed
* 11\. Passed
* 12\. Passed
* 13\. Passed 
* 14\. Not tested (not possible to implement on server's side)
* 15\. Passed


## Feedback on Test Specifications and Issues

* Test 8: error on test specifications, the request payload is different 8a-8b
* Test 14 is not possible to test on most servers.
* Test 12 is only correctly described for scenarios where the response is not piggibacked on the ACK. If that's the case, the client is not requested to send an ACK back in case of error.
* New [issue #127](https://github.com/core-wg/oscoap/issues/107): What should the responses to GET seqno=::07 observe be?
    - 2.05 seqno=implied 80::07 "1", 2.05 seqno=::01 "2", ...
    - 2.05 seqno=::01 "1", 2.05 seqno=::02 "2", ...
    - Christian, Jim: "Accepting both would make sense"
        + Christian: esp.  w/rt to upcoming multicast applications
        + Christian (later note): Might also be useful for clients that can't afford message deduplication. If my constrained server receives a CON again after having sent the payload in an ACK, the response might have gotten lost. Instead of memorizing the response in full or making very sure I produce the very same bytes again, I could just send a (now current) response again, but as I've already used the flipped-space partial IV, I have to use one of my own seqnos.
* A number of other issues were created following this interop: [issue #131](https://github.com/core-wg/oscoap/issues/107) [issue #132](https://github.com/core-wg/oscoap/issues/107) [issue #133](https://github.com/core-wg/oscoap/issues/107)