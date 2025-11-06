import random

def gcd(a, b):
    """Calculates the greatest common divisor of a and b."""
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """
    Finds the modular inverse of e modulo phi.
    Returns d such that e*d % phi = 1.
    Uses Python's built-in pow function for reliability.
    We tried implementing Extended Euclidean Algorithm but had bugs,
    so we're using the built-in instead which is more reliable.
    """
    # Python 3.8+ supports pow(e, -1, phi) for modular inverse
    return pow(e, -1, phi)

def is_prime(n, k=5):
    """
    Miller-Rabin primality test. A simple probabilistic check.
    Returns True if n is *probably* prime, False if composite.
    """
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
        
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime_candidate(length):
    """Generate an odd number of 'length' bits."""
    p = random.getrandbits(length)
    # Make it odd
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=128):
    """Generate a prime number of 'length' bits."""
    p = 4
    while not is_prime(p, 5):
        p = generate_prime_candidate(length)
    return p

def generate_keypair(p, q):
    """
    Generates an RSA keypair given two primes p and q.
    Returns (public_key, private_key)
    """
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    elif p == q:
        raise ValueError("p and q cannot be equal.")

    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537 # Common choice for e
    if gcd(e, phi) != 1:
        # Find an e that is coprime to phi
        e = 3
        while gcd(e, phi) != 1:
            e += 2
            
    d = mod_inverse(e, phi)
    
    # Public key: (e, n), Private key: (d, n)
    return ((e, n), (d, n))
