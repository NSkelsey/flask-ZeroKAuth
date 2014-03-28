from utils import group_constants, randbits
from utils import _hash as H


class Server:
    def __init__(self):
        N, g, k = group_constants()
        self.N = N
        self.g = g
        self.k = k
        self.users = {}

    def store_user(self, username, tup):
        """Stores username, tup in Server object
        where tup is (s, v)"""
        self.users[username] = tup
        self.cur = username

    def compute_B(self, username, A):
        self.A = A
        # TODO check if A % N == 0
        s, v = self.users[username]
        b = randbits() 
        self.b = b

        B = (self.k * v + pow(self.g, b, self.N)) % self.N
        self.B = B
        return (s, B)

    def compute_secret(self):
        A, N, b, B = self.A, self.N, self.b, self.B
        v = self.users[self.cur][1]
        u = H(A, B)
        S_s = pow(A * pow(v, u, N), b, N)
        self.S = S_s
        print S_s
        K_s = H(S_s)
        return K_s

if __name__ == '__main__':
    from srp_client import Client
    carol = Client()
    server = Server()
    # Establishment
    s, v = carol.establish('carol', 'thisissecure')
    server.store_user('carol', (s, v))

    # Authentication
    I, A = carol.compute_A()
    
    s, B = server.compute_B(I, A)
    
    kc = carol.compute_secret('thisissecure', s, B)

    ks = server.compute_secret()

    assert kc == ks


