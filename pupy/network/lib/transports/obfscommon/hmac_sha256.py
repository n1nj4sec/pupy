import hashlib
import hmac

def hmac_sha256_digest(key, msg):
    """
    Return the HMAC-SHA256 message authentication code of the message
    'msg' with key 'key'.
    """

    return hmac.new(key, msg, hashlib.sha256).digest()
