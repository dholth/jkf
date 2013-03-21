# JSON Key Fingerprints (JKF) prototype.
# (Not based on any standard.)

import hashlib
import json
from collections import OrderedDict

HASHABLE = { 
        # key type : set(fields) mapping. JKF only hashes the public
        # non-metadata fields from the JSON Web Key.
        "RSA":{'kty', 'n', 'e'},
        "EC":{'kty', 'crv', 'x', 'y'},
        "Ed25519":{'kty', 'vk'}
        }

def normalize(jwk):
    """Return only the hashable portion of a JSON Web Key as an OrderedDict."""
    return OrderedDict(sorted((k, jwk[k]) for k in HASHABLE[jwk['kty']]))

def dumps(jwk):
    """Return JSON without whitespace as utf-8 encoded bytes."""
    return json.dumps(jwk, separators=(",", ":")).encode('utf-8')

def fingerprint(jwk, algorithm="sha256"):
    """Return the fingerprint of the given JSON Web Key as a hashlib object."""
    h = hashlib.new(algorithm)
    h.update(dumps(normalize(jwk)))
    return h
