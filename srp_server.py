from utils import group_constants, randbits
from utils import _hash as H

class Verifier:
    def __init__(self, **kwargs):
        for key in kwargs:
            setattr(self, key, kwargs[key])
        N, g, k = group_constants()
        self.N = N
        self.g = g
        self.k = k

        assert type(self.s) == long

    def store_user(self, username, tup):
        """Initializes verifier object with (I s,v)"""
        s, v = tup
        assert type(s) == long and type(v) == long

        self.s, self.v = tup
        self.I = username

    def compute_B(self, A):
        """Derives B and returns (s, B)"""
        assert type(A) == long   

        # assertions required by SRP-6
        assert A % self.N != 0
        self.A = A
        s, v = self.s, self.v
        b = randbits() 
        self.b = b

        B = (self.k * v + pow(self.g, b, self.N)) % self.N
        self.B = B
        return (s, B)

    def compute_secret(self):
        A, N, b, B = self.A, self.N, self.b, self.B
        v = self.v
        u = H(A, B)
        S_s = pow(A * pow(v, u, N), b, N)
        self.S = S_s
        K_s = H(S_s)
        self.K = K_s
        return K_s

    def verify_M1(self, M1):
        assert type(M1) == long
        I, s = self.I, self.s
        N, g  = self.N, self.g
        A, B, K = self.A, self.B, self.K
        M1_s = H(H(N) ^ H(g), H(I), s, A, B, K)
        print M1_s
        self.M1 =  M1_s
        assert M1 == M1_s

    def compute_M2(self):
        A, M1, K = self.A, self.M1, self.K
        M2 = H(A, M1, K)
        return M2

    def params(self):
        """A cheap hack for now"""
        return self.__dict__

if __name__ == '__main__':
    from srp_client import Client
    carol = Client()
    server = Verifier()
    # Establishment
    s, v = carol.establish('carol', 'thisissecure')
    server.store_user('carol', (s, v))

    # Authentication
    I, A = carol.compute_A()
    
    s, B = server.compute_B(A)
    
    kc = carol.compute_secret('thisissecure', s, B)

    ks = server.compute_secret()
    assert kc == ks

    M1 = carol.generate_M1()
    server.verify_M1(M1)
    M2 = server.compute_M2()
    carol.verify_M2(M2)
