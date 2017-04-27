# OSCOAP Interop Recap

26th of March 2017, 17:00-18:00 CET

## Participants

- Christian Amsüss
- Jim Schaad
- Francesca Palombini

## Note takers

Francesca

## Documentation

### \[1\]: [Test specification provided](https://github.com/EricssonResearch/OSCOAP/releases/tag/interop-27-02-2017)

### \[2\]: [OSCOAP version implemented](https://github.com/core-wg/oscoap/releases/tag/interop-26-03-2017)

## Summary

This second interop was carried on during the Hackathon for IETF98. Two implementations were tested: Christian's and Jim's on OSCOAP v-02 (see \[2\]). The set of tests was run on a first round with Jim's server and Christian's client, and on a second round with Jim's client and Christian's server.
Jim and Christian have described the outcome of each test during the run as successful (passed) or not (failed) if the outcome was the one expected according to the test specification \[1\]. They have also captured the traffic and shared it with us, to allow for a more extensive analysis of the results.

In short, the interop for OSCOAP was successful, and the implementation could interact as expected, for the set of tests provided.

## Details



## notes:

Compared to the verision in \[2\], the implementors proposed and implemented one more detail that was as a consequence added in later revisions in the draft: they moved the parameters in the protected COSE header to the unprotected COSE header. (See [issue #107](https://github.com/core-wg/oscoap/issues/107))

### Client: Christian's, Server: Jim's

* 1\. aad failure because no response back, with ipv6, with ipv4 there is a response, but aad doesnt decrypt properly. After comparing the external aad
(Jim: 86-01-18-45-40-0C-46-63-6C-69-65-6E-74-41-01), Christian was using Sid of the server instead of client in the response aad. When that was fixed, the test passed.
* 2\. pass *
* 3\. pass *
* 4\. failed: weird debugging step was failing on jim's side. After commenting it, pass
* 5\. pass
* 6\. pass
* 7\. pass
* 8\. pass (invalid ciphertext)
* 9\. Christian's issue from implementation error. sender id and recipient id inversion
* 10\. pass
* 14\. pass on Chris, Jim sent an error while spec says no error back

### Client: Jim's, Server: Christian's

* 1\. pass
* 2\. pass
* 3\. pass (After correction of test implem (second=2) on Jim's side)
* 4\. pass
* 5\. pass
* 6\. pass
* 7\. pass
* 8\. pass (Error1 on Jim's side)
* 9\. pass
* 10\. pass
* 14\. pass 

* disagree on what CoAP options to send back but oscoap passed

## Feedback on Test Specifications

From Christian: we should add a case where role reversal actually happens, eg. "Client POSTs to /reflect-my-color/, server responds with
2.01 and Location: /reflect-my-color/1, server GETs the client's /color and makes it available at /reflect-my-color/1, client GETs /reflect-my-color/1".
