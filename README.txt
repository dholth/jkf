jkf
===

Prototype JSON Key Fingerprints implementation.

JSON Key Fingerprints is a method for hashing a JSON Web Key. The
resulting value, called a fingerprint, can be recomputed from another
representation of the same key and used as a short identifier.

JSON Web Keys do not currently have a standard fingerprinting scheme. This
scheme is not based on any standard but is very straightforward. The
implementation takes the non-metadata members of a JWK (just the public
values used by the crypto math, and not the "kid" or "use" flags), sorts
them, and outputs UTF-8 encoded JSON with no whitespace separators. The
hash of that binary string is the JSON Key Fingerprint.

