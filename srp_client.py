from binascii import hexlify

from utils import randbits, group_constants
from utils import _hash as H


class Client:
    def __init__(self):
        """Initializes a client object with a defined generator"""
        (N, g, k) = group_constants()
        self.N = N
        self.g = g
        self.k = k

    def establish(self, username, password):
        """Takes a username and password and returns a tuple
        of (salt, v)
        """
        self.username = username
        s = randbits(64)
        x = H(s, password)
        v = pow(self.g, x, self.N)
        return (s, v) 

    def test_est(self):
        """example usage"""
        uname, pw = ('nick', 'shittypw')
        s, v = self.establish(uname, pw)
        print uname, (s, v)

    def compute_A(self):
        a = randbits()
        self.a = a
        A = pow(self.g, a, self.N)
        self.A = A
        return (self.username, A)

    def compute_secret(self, password, s, B):
        self.s = s
        self.B = B
        u = H(self.A, B)
        # TODO check conditions
        x = H(s, password) 
        N, g, k, a  = self.N, self.g, self.k, self.a
        S_c = pow(B - k*pow(g, x, N), a + u*x, N)

        self.S = S_c
        print S_c
        K_c = H(S_c)
        return K_c



if __name__ == '__main__':
    c = Client()
    c.test_est()

