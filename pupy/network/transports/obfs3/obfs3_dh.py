import binascii

from ..obfscommon import rand
from ..obfscommon import modexp

def int_to_bytes(lvalue, width):
    fmt = '%%.%dx' % (2*width)
    return binascii.unhexlify(fmt % (lvalue & ((1L<<8*width)-1)))

class UniformDH:
    """
    This is a class that implements a DH handshake that uses public
    keys that are indistinguishable from 192-byte random strings.

    The idea (and even the implementation) was suggested by Ian
    Goldberg in:
    https://lists.torproject.org/pipermail/tor-dev/2012-December/004245.html
    https://lists.torproject.org/pipermail/tor-dev/2012-December/004248.html

    Attributes:
    mod, the modulus of our DH group.
    g, the generator of our DH group.
    group_len, the size of the group in bytes.

    priv_str, a byte string representing our DH private key.
    priv, our DH private key as an integer.
    pub_str, a byte string representing our DH public key.
    pub, our DH public key as an integer.
    shared_secret, our DH shared secret.
    """

    # 1536-bit MODP Group from RFC3526
    mod = int(
        """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
           29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
           EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
           E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
           EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
           C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
           83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
           670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF""".replace(' ','').replace('\n','').replace('\t',''), 16)
    g = 2
    group_len = 192 # bytes (1536-bits)

    def __init__(self, private_key = None):
        # Generate private key
        if private_key != None:
            if len(private_key) != self.group_len:
                raise ValueError("private_key is a invalid length (Expected %d, got %d)" % (group_len, len(private_key)))
            self.priv_str = private_key
        else:
            self.priv_str = rand.random_bytes(self.group_len)
        self.priv = int(binascii.hexlify(self.priv_str), 16)

        # Make the private key even
        flip = self.priv % 2
        self.priv -= flip

        # Generate public key
        #
        # Note: Always generate both valid public keys, and then pick to avoid
        # leaking timing information about which key was chosen.
        pub = modexp.powMod(self.g, self.priv, self.mod)
        pub_p_sub_X = self.mod - pub
        if flip == 1:
            self.pub = pub_p_sub_X
        else:
            self.pub = pub
        self.pub_str = int_to_bytes(self.pub, self.group_len)

        self.shared_secret = None

    def get_public(self):
        return self.pub_str

    def get_secret(self, their_pub_str):
        """
        Given the public key of the other party as a string of bytes,
        calculate our shared secret.

        This might raise a ValueError since 'their_pub_str' is
        attacker controlled.
        """
        their_pub = int(binascii.hexlify(their_pub_str), 16)

        self.shared_secret = modexp.powMod(their_pub, self.priv, self.mod)
        return int_to_bytes(self.shared_secret, self.group_len)

