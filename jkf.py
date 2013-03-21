# JSON Key Fingerprints prototype
# (not based on any specification)

import hashlib
import json
from collections import OrderedDict

HASHABLE = {
        "RSA":{'kty', 'n', 'e'},
        "EC":{'kty', 'crv', 'x', 'y'},
        "Ed25519":{'kty', 'vk'}
        }

def normalize(jwk):
    """Return only the hashable portion of a JSON Web Key as an OrderedDict."""
    return OrderedDict(sorted((k, jwk[k]) for k in HASHABLE[jwk['kty']]))

def dumps(jwk):
    """Return JSON without whitespace as bytes."""
    return json.dumps(jwk, separators=(",", ":")).encode('utf-8')

def fingerprint(jwk, algorithm="sha256"):
    """Return the fingerprint of the given JSON Web Key as a hashlib object."""
    h = hashlib.new(algorithm)    
    h.update(canonicalize(dumps(jwk)))
    return h
