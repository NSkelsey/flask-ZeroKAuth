from utils import group_constants, randbits
from utils import _hash as H

class Verifier:
    def __init__(self, **kwargs):
        """
        Initializes a verifier object from the given keyword args
        to run compute be we need s, A, I
        """
        for key in kwargs:
            setattr(self, key, kwargs[key])
        N, g, k = group_constants()
        self.N = N
        self.g = g
        self.k = k

    def compute_B(self, A):
        """Derives B and returns (s, B)"""
        assert type(A) == long   

        # assertions required by SRP-6
        assert A % self.N != 0
        self.A = A
        b = randbits() 
        self.b = b

        B = (self.k * self.v + pow(self.g, b, self.N)) % self.N
        self.B = B
        return (self.s, B)

    def compute_secret(self):
        """
        Computes the servers secret using its updated internal state
        """
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
        self.M1 =  M1_s
        assert M1 == M1_s

    def compute_M2(self):
        A, M1, K = self.A, self.M1, self.K
        M2 = H(A, M1, K)
        return M2

    def params(self):
        """A cheap hack for now"""
        return self.__dict__

def params_equal(client, server):
    """asserts that all of the objects shared attributes are equal"""
    c = client.__dict__
    s = client.__dict__

    for k, v in c.iteritems():
        if k in s:
            assert v == s[k], "Key: %s is not equal:\nC:%s\t\nS:%s\t\n" % (k, v, s[k])

if __name__ == '__main__':
    from srp_client import Client
    carol = Client()
    username, password = 'carol', 'thisisecure'
    # Establishment
    s, v = carol.establish(password=password)

    # Authentication
    A = carol.compute_A(username=username)
    
    server = Verifier(s=s, v=v, I=username)
    s1, B = server.compute_B(A=A)
    
    kc = carol.compute_secret(password=password, s=s, B=B)

    ks = server.compute_secret()
    params_equal(carol, server)
    assert kc == ks


    M1 = carol.generate_M1()
    server.verify_M1(M1=M1)
    M2 = server.compute_M2()
    carol.verify_M2(M2)

