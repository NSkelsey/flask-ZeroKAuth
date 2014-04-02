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

    def establish(self, password):
        """Takes a password and returns a tuple
        of (salt, v)
        """
        assert type(password) == str
        s = randbits(64)
        x = compute_x(s, password)
        self.x = x
        v = pow(self.g, x, self.N)
        self.v = v
        return (s, v) 

    def test_est(self):
        """example usage"""
        uname, pw = ('nick', 'shittypw')
        s, v = self.establish(uname, pw)
        print uname, (s, v)

    def compute_A(self, username):
        assert type(username) == str
        a = randbits()
        self.a = a
        self.I = username
        A = pow(self.g, a, self.N)
        self.A = A
        return A

    def compute_secret(self, password, s, B):
        """Computes the shared secret with pw, s and B
        returns K_c where K = H(secret)"""
        assert type(password) == str
        assert type(s) == long
        assert type(B) == long
        self.s = s
        self.B = B
        u = H(self.A, B)
        # assertions required by SRP-6
        # TODO test in hostile circumstances
        assert u != 0
        assert B % self.N != 0

        x = compute_x(s, password)
         
        N, g, k, a  = self.N, self.g, self.k, self.a
        S_c = pow(B - k*pow(g, x, N), a + u*x, N)
        self.S = S_c
        K_c = H(S_c)
        self.K = K_c
        return K_c

    def generate_M1(self):
        N, g, I,  = self.N, self.g, self.I
        s, A, B, K = self.s, self.A, self.B, self.K
        M1 = H(H(N) ^ H(g), H(I), s, A, B, K)
        self.M1 = M1
        return M1

    def verify_M2(self, M2):
        assert type(M2) == long
        A, M1, K = self.A, self.M1, self.K  
        M2_c = H(A, M1, K)
        assert M2 == M2_c
        return M2 == M2_c
     
def compute_x(s, password):
    x = H(s, password)
    return x

if __name__ == '__main__':
    c = Client()
    c.test_est()
