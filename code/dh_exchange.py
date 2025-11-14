import random
# We import the RSA functions *only* for the defense part
from rsa_utils import generate_keypair

# Publicly known parameters for demonstration
P = 23  # A small prime
G = 5   # A generator

def generate_private_key():
    """Generates a private key."""
    return random.randint(2, P - 2)

def generate_public_key(private_key):
    """Generates a public key from a private key."""
    return pow(G, private_key, P)

def get_shared_secret(public_key, private_key):
    """Computes the shared secret."""
    return pow(public_key, private_key, P)

def simulate_normal_exchange():
    """Simulates a normal, uninterrupted D-H exchange."""
    print("--- Normal D-H Exchange ---")
    # Ana's keys
    a_private = generate_private_key()
    a_public = generate_public_key(a_private)
    print(f"Ana's private: {a_private}, public: {a_public}")

    # Phara's keys
    b_private = generate_private_key()
    b_public = generate_public_key(b_private)
    print(f"Phara's private: {b_private}, public: {b_public}")

    # Key Exchange
    s_ana = get_shared_secret(b_public, a_private)
    s_phara = get_shared_secret(a_public, b_private)
    
    print(f"Ana's computed secret: {s_ana}")
    print(f"Phara's computed secret:   {s_phara}")
    
    if s_ana == s_phara:
        print("SUCCESS: Secrets match.\n")
    else:
        print("FAILURE: Secrets do NOT match.\n")

def simulate_mitm_attack():
    """Simulates a Man-in-the-Middle (MitM) attack."""
    print("--- Man-in-the-Middle (MitM) Attack ---")
    # Ana's keys
    a_private = generate_private_key()
    a_public = generate_public_key(a_private)
    print(f"Ana's private: {a_private}, public: {a_public}")

    # Phara's keys
    b_private = generate_private_key()
    b_public = generate_public_key(b_private)
    print(f"Phara's private: {b_private}, public: {b_public}")
    
    # Doomfist's (Attacker) keys
    m_private = generate_private_key()
    m_public = generate_public_key(m_private)
    print(f"Doomfist's private: {m_private}, public: {m_public}")

    # Doomfist intercepts the exchange
    print("\nDoomfist intercepts and replaces the public keys...")
    
    # Ana computes a secret with Doomfist's key
    s_ana = get_shared_secret(m_public, a_private)
    # Phara computes a secret with Doomfist's key
    s_phara = get_shared_secret(m_public, b_private)
    
    # Doomfist computes secrets with both Ana and Phara
    s_doomfist_ana = get_shared_secret(a_public, m_private)
    s_doomfist_phara = get_shared_secret(b_public, m_private)
    
    print(f"Ana's computed secret (with Doomfist): {s_ana}")
    print(f"Phara's computed secret (with Doomfist):   {s_phara}")
    print(f"Doomfist's computed secret (with Ana): {s_doomfist_ana}")
    print(f"Doomfist's computed secret (with Phara):   {s_doomfist_phara}")
    
    if s_ana == s_doomfist_ana and s_phara == s_doomfist_phara and s_ana != s_phara:
        print("SUCCESS: MitM Attack successful.\n")
    else:
        print("FAILURE: MitM Attack failed.\n")

def simulate_authenticated_exchange():
    """Simulates the authenticated D-H exchange as a defense."""
    print("--- Authenticated D-H Exchange (Defense) ---")
    
    # Setup: Ana and Phara need RSA keys for signing
    print("\nGenerating RSA keys for Ana and Phara...")
    p, q = 61, 53
    a_rsa_pub, a_rsa_priv = generate_keypair(p, q)
    p, q = 67, 71
    b_rsa_pub, b_rsa_priv = generate_keypair(p, q)
    
    # Simple "sign" and "verify" functions
    def sign(message, private_key):
        d, n = private_key
        # Simplified: sign the number directly instead of its hash
        return pow(message, d, n)

    def verify(message, signature, public_key):
        e, n = public_key
        decrypted_sig = pow(signature, e, n)
        return message == decrypted_sig

    # --- Exchange ---
    
    # Ana creates her D-H key and signs it
    a_private = generate_private_key()
    a_public = generate_public_key(a_private)
    a_sig = sign(a_public, a_rsa_priv)
    
    # Phara creates her D-H key and signs it
    b_private = generate_private_key()
    b_public = generate_public_key(b_private)
    b_sig = sign(b_public, b_rsa_priv)
    
    # Doomfist tries to intercept with a fake key and signature
    m_private = generate_private_key()
    m_public = generate_public_key(m_private)
    m_fake_sig = 12345 # Doomfist can't create a valid signature
    
    print("\nDoomfist tries to substitute a fake key and signature...")
    
    # Phara receives Doomfist's key, but verifies it with Ana's public RSA key
    if not verify(m_public, m_fake_sig, a_rsa_pub):
        print("Phara: Signature verification FAILED. Attack detected.")
    else:
        print("Phara: Signature OK. (This should not happen!)")
        
    # Ana receives Doomfist's key, but verifies it with Phara's public RSA key
    if not verify(m_public, m_fake_sig, b_rsa_pub):
        print("Ana: Signature verification FAILED. Attack detected.")
    else:
        print("Ana: Signature OK. (This should not happen!)")

    # Ana and Phara now exchange their real, signed keys
    print("\nAna and Phara exchange their real, signed keys.")
    
    # Phara verifies Ana's real key
    phara_verifies_ana = verify(a_public, a_sig, a_rsa_pub)
    # Ana verifies Phara's real key
    ana_verifies_phara = verify(b_public, b_sig, b_rsa_pub)
        
    if phara_verifies_ana and ana_verifies_phara:
        print("Ana and Phara: Signatures are valid. Proceeding.")
        s_ana = get_shared_secret(b_public, a_private)
        s_phara = get_shared_secret(a_public, b_private)
        print(f"Ana's secret: {s_ana}")
        print(f"Phara's secret:   {s_phara}")
        if s_ana == s_phara:
            print("SUCCESS: Defense worked. MitM was prevented.\n")
        else:
            print("FAILURE: Defense failed.\n")
    else:
        print("FAILURE: Real signatures could not be verified.\n")

if __name__ == "__main__":
    simulate_normal_exchange()
    simulate_mitm_attack()
    simulate_authenticated_exchange()
