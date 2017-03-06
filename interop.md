# OSCOAP Interop Recap

27th of February 2017, 8:00-10:30 CET

## Participants

- Christian Amsüss
- Jim Schaad
- Ludwig Seitz
- Mališa Vučinić
- Martin Gunnarsson
- Göran Selander
- Francesca Palombini

## Note takers

Francesca, Christian

## Documentation

### \[1\]: {#ref-1}
[Test specification provided:](https://github.com/EricssonResearch/OSCOAP/releases/tag/interop-27-02-2017)

### \[2\]: {#ref-2}
[OSCOAP version implemented:](https://github.com/core-wg/oscoap/releases/tag/interop-27-02-17)

## Summary

Because of the short timeslot and connectivity issues, only two implementations were tested: Christian's and Jim's. The set of tests was run on a first round with Jim's client and Christian's server, and on a second round with Jim's server and Christian's client.
Jim and Christian have described the outcome of each test during the run as successful (passed) or not (failed) if the outcome was the one expected according to the test specification [[1]](#1). They have also captured the traffic and shared it with us, to allow for a more extensive analysis of the results.

In short, the interop was successful, and the implementation could interact as expected, for the set of tests provided.

## Details

### Client: Jim's, Server: Christian's

* 1\. Initially failed because of difference sequence number type (byte vs int) in external_aad structure. After correction, passed
* 2\. A strange content-format was sent from server's side (0x46) for this and some of the following tests. OSCOAP behavior was as expected, though, so passed
* 3\. The client expected a different option than the one specified in [[1]](#ref-1). Considering that, OSCOAP behaved as expected, so passed
* 4\. Passed
* 5\. Passed
* 6\. Passed
* 7\. Passed
* 8\. and 9. were not exactly run as specified because too complicated to implement, but an equivalent of the tests was run (Client's context derivation was given a different master secret, creating a different sender key with same context identifier), so passed
* 10\. The test was unclear in the test specification, so it was skipped 
* 11\. to 13. were skipped because it was not possible in the client implementation to modify the security context.
* 14\. Passed 
* 15\. Passed (the behavior was recreated by restarting the server between 2 consequent requests) 
* 16\. Passed 
* 17\. Passed 

Additional tests:

* Deliberate modification to CoAP version number on client side: failed verification on server side, so passed.
* Client sends 2B sequence numbers: passed
* Client sends Uri_Query unprotected: server discards it, so passed.
* Client sends unknown Cid: passed

## Client: Christian's, Server: Jim's

* 1\. Passed
* 2\. Passed
* 3\. Passed
* 4\. (Strange content-format re-appeared) Passed
* 5\. Initial problem due to their dependence on test 4, but OSCOAP behavior as expected passed
* 6\. Passed
* 7\. Passed
* 8\. Passed, even though the behavior was slightly different from specified in [[1]](#ref-1) the server sent volontarily an error response back to avoid CoAP retransmission.
* 9\. Passed, same as 8\.
* 10\. Passed, same as 8\.
* 11\. Passed
* 12\. Passed
* 13\. Passed
* 14\. Passed
* 15\. Passed
* 16\. Was skipped, as it was not implemented on the server, since it was difficult to implement
* 17\. Passed with a minor modification on Uri-Path option

## Feedback on Test specification

* Any of 8-9-10 and 11-12-13 is enough. For example instead of 8-9-10-11-12-13, only run 8 and 11, or 10 and 13. This would test the case where the contexts are incorrectly derived.
* Extra tests are needed if the sender ID is sent in the request
* There was discussion about the necessity of test 16, we should re-evaluate if this is not tested by the set of all the other tests
* Would be good to have one "Test 0" as an non-protected CoAP request, to test connectivity
* More guidance on behavior on CoAP level would have been appreciated (for example CoAP return codes) in the test specifications
* Some tests seemed dependent on the one before (for example, POST was supposed to create a resource that was used afterward), it would have been better to have independent tests, that would only depend on the request URI and method. Specify that the server must allow execution of the tests in any sequence.
* Consider specifying a resource on server side to reset the security context to run a specific test