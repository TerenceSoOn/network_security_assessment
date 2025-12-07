import random

def gcd(a, b):
    """Calculates the greatest common divisor of a and b."""
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """
    Finds the modular inverse of e modulo phi.
    (e*d) % phi = 1
    """
    # We use Python's built-in pow(e, -1, phi) for modular inverse
    # because it's fast and reliable.
    return pow(e, -1, phi)

def is_prime(n, k=5):
    """
    Miller-Rabin primality test.
    Returns True if n is probably prime.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
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
    # Set the MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=128):
    """Generate a prime number of 'length' bits."""
    p = 4
    # Keep generating candidates until one is prime
    while not is_prime(p, 5):
        p = generate_prime_candidate(length)
    return p

def generate_keypair(p, q):
    """
    Generates an RSA keypair from two primes, p and q.
    """
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    if p == q:
        raise ValueError("p and q cannot be equal.")

    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537 # A common choice for e
    if gcd(e, phi) != 1:
        # Find an e that is coprime to phi if 65537 is not
        e = 3
        while gcd(e, phi) != 1:
            e += 2
            
    d = mod_inverse(e, phi)
    
    # Public key: (e, n), Private key: (d, n)
    return ((e, n), (d, n))
