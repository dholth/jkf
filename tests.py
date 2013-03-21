import jkf
import nose.tools

# Firs 2 keys from http://self-issued.info/docs/draft-ietf-jose-json-web-key.html#JWKSet
keys = [
        {
            "kty":"EC",
            "crv":"P-256",
            "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "use":"enc",
            "kid":"1"
        }, {
            "kty":"RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e":"AQAB",
            "alg":"RS256",
            "kid":"2011-04-29"
        }, {
            "vk": "tmAYCrSfj8gtJ10v3VkvW7jOndKmQIYE12hgnFu3cvk", 
            "kty": "Ed25519"
        }
       ]

expected = [
 '727f88fd634c0a57a1895a79d62ff4569384356d6ea447ab03cb046a6e619feb',
 '3736cbb1787cb8309c77ee8c3705c5e16ffb9e859715901f1e4c59b11182f57b',
 '9d3a75e802c2ed7831b4a0f9867a6c09226d9394e5c5a378c53c09161d557726'
 ]

def test_jkf():
    a = []
    b = []

    for key in keys:
        a.append(jkf.fingerprint(key).hexdigest())

    for key in keys:
        copy = dict(key)
        for k in ['kid', 'alg', 'use']:
            if k in copy:
                del copy[k]
        b.append(jkf.fingerprint(key).hexdigest())

    for f1, f2, f3 in zip(a, b, expected):
        assert f1 == f2
        assert f1 == f3

@nose.tools.raises(KeyError)
def test_bad_algo():
    jkf.fingerprint({'kty':'DOG'})

@nose.tools.raises(KeyError)
def test_missing_param():
    jkf.fingerprint({'kty':'RSA'})

