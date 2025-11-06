import random
# We import the RSA functions *only* for the defense part
from rsa_utils import generate_keypair

# Publicly known parameters (for demonstration)
# In a real system, these would be much larger (like 2048 bits)
# We're using small numbers so we can verify by hand
P = 23  # A small prime
G = 5   # A generator

def generate_private_key():
    """Generates a private key."""
    return random.randint(2, P - 2)

def generate_public_key(private_key):
    """Generates a public key."""
    return pow(G, private_key, P)

def get_shared_secret(public_key, private_key):
    """Computes the shared secret."""
    return pow(public_key, private_key, P)

def simulate_normal_exchange():
    """Simulates a normal, uninterrupted D-H exchange."""
    print("--- 1. Normal D-H Exchange ---")
    # Ana
    a_private = generate_private_key()
    a_public = generate_public_key(a_private)
    print(f"Ana's private: {a_private}, public: {a_public}")

    # Phara
    b_private = generate_private_key()
    b_public = generate_public_key(b_private)
    print(f"Phara's private: {b_private}, public: {b_public}")

    # Exchange
    print("\nAna and Phara exchange public keys...")
    s_ana = get_shared_secret(b_public, a_private)
    s_phara = get_shared_secret(a_public, b_private)
    
    print(f"Ana's computed secret: {s_ana}")
    print(f"Phara's computed secret:   {s_phara}")
    
    if s_ana == s_phara:
        print("SUCCESS: Secrets match.\n")
    else:
        print("FAILURE: Secrets do NOT match.\n")
    return s_ana, s_phara

def simulate_mitm_attack():
    """Simulates a Man-in-the-Middle (MitM) attack."""
    print("--- 2. Man-in-the-Middle (MitM) Attack ---")
    # Ana
    a_private = generate_private_key()
    a_public = generate_public_key(a_private)
    print(f"Ana's private: {a_private}, public: {a_public}")

    # Phara
    b_private = generate_private_key()
    b_public = generate_public_key(b_private)
    print(f"Phara's private: {b_private}, public: {b_public}")
    
    # Doomfist (Attacker)
    m_private = generate_private_key()
    m_public = generate_public_key(m_private)
    print(f"Doomfist's private: {m_private}, public: {m_public}")

    # Exchange
    print("\nDoomfist intercepts the exchange...")
    # Ana sends A to Phara, Doomfist intercepts
    # Doomfist sends M to Phara (as Ana)
    # Phara sends B to Ana, Doomfist intercepts
    # Doomfist sends M to Ana (as Phara)
    
    # Ana computes secret with Doomfist
    s_ana = get_shared_secret(m_public, a_private)
    # Phara computes secret with Doomfist
    s_phara = get_shared_secret(m_public, b_private)
    
    # Doomfist computes both secrets
    s_doomfist_ana = get_shared_secret(a_public, m_private)
    s_doomfist_phara = get_shared_secret(b_public, m_private)
    
    print(f"Ana's computed secret (with Doomfist): {s_ana}")
    print(f"Phara's computed secret (with Doomfist):   {s_phara}")
    print(f"Doomfist's computed secret (with Ana): {s_doomfist_ana}")
    print(f"Doomfist's computed secret (with Phara):   {s_doomfist_phara}")
    
    if s_ana == s_doomfist_ana and s_phara == s_doomfist_phara and s_ana != s_phara:
        print("SUCCESS: MitM Attack successful. Doomfist controls both channels.\n")
    else:
        print("FAILURE: MitM Attack failed.\n")
    return s_ana, s_phara, (s_doomfist_ana, s_doomfist_phara)

def simulate_authenticated_exchange():
    """Simulates the authenticated D-H exchange (defense)."""
    print("--- 3. Authenticated D-H Exchange (Defense) ---")
    
    # Setup: Ana and Phara need RSA keys for signing
    # (Using small primes for this demo)
    print("\nGenerating RSA keys for Ana and Phara...")
    p, q = 61, 53
    a_rsa_pub, a_rsa_priv = generate_keypair(p, q)
    p, q = 67, 71
    b_rsa_pub, b_rsa_priv = generate_keypair(p, q)
    
    # Simple "sign" and "verify" functions using RSA
    def sign(message, private_key):
        d, n = private_key
        # In a real app, you would hash the message first
        # Here we just sign the number
        return pow(message, d, n)

    def verify(message, signature, public_key):
        e, n = public_key
        decrypted_sig = pow(signature, e, n)
        return message == decrypted_sig

    # --- Exchange ---
    
    # Ana
    a_private = generate_private_key()
    a_public = generate_public_key(a_private)
    a_sig = sign(a_public, a_rsa_priv) # Ana signs her public key
    
    # Phara
    b_private = generate_private_key()
    b_public = generate_public_key(b_private)
    b_sig = sign(b_public, b_rsa_priv) # Phara signs his public key
    
    # Doomfist tries to intercept
    m_private = generate_private_key()
    m_public = generate_public_key(m_private)
    # Doomfist *cannot* create a valid signature for m_public
    # that verifies with Ana's or Phara's public key.
    # She can try to sign it with her own (unknown) key.
    m_fake_sig = 12345 # Or just a random number
    
    print("Ana sends (A, Sig(A)) to Phara...")
    print("Phara sends (B, Sig(B)) to Ana...")
    print("\nDoomfist intercepts and tries to substitute (M, Fake_Sig)...")
    
    # Phara receives Doomfist's key M, but verifies it with ANA's pubkey
    if not verify(m_public, m_fake_sig, a_rsa_pub):
        print("Phara: Signature verification FAILED. Attack detected.")
    else:
        # This part should not be reached
        print("Phara: Signature OK. (This should not happen!)")
        
    # Ana receives Doomfist's key M, but verifies it with PHARA's pubkey
    if not verify(m_public, m_fake_sig, b_rsa_pub):
        print("Ana: Signature verification FAILED. Attack detected.")
    else:
        # This part should not be reached
        print("Ana: Signature OK. (This should not happen!)")

    # Ana and Phara only proceed if signatures are valid
    # They exchange their *real* keys
    print("\nAna and Phara ignore Doomfist and exchange their real, signed keys.")
    
    # Phara verifies Ana's real key and signature
    phara_verifies_ana = verify(a_public, a_sig, a_rsa_pub)
    # Ana verifies Phara's real key and signature
    ana_verifies_phara = verify(b_public, b_sig, b_rsa_pub)
        
    if phara_verifies_ana and ana_verifies_phara:
        print("Ana and Phara: Signatures are valid. Proceeding with real keys.")
        s_ana = get_shared_secret(b_public, a_private)
        s_phara = get_shared_secret(a_public, b_private)
        print(f"Ana's secret: {s_ana}")
        print(f"Phara's secret:   {s_phara}")
        if s_ana == s_phara:
            print("SUCCESS: Defense worked. MitM was prevented.\n")
        else:
            print("FAILURE: Defense failed.\n")
    else:
        if not phara_verifies_ana:
            print("Phara: Could not verify Ana's real signature.")
        if not ana_verifies_phara:
            print("Ana: Could not verify Phara's real signature.")
        print("FAILURE: Real signatures could not be verified.\n")

if __name__ == "__main__":
    simulate_normal_exchange()
    simulate_mitm_attack()
    simulate_authenticated_exchange()

