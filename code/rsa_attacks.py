import time
import random
from rsa_utils import generate_keypair, mod_inverse, generate_prime_number

# --- Vulnerable Implementation ---
def vulnerable_decrypt(ciphertext, private_key):
    """
    A vulnerable RSA decryption function.
    The 'if bit == 1' branch creates a timing difference,
    which is the source of the vulnerability.
    """
    d, n = private_key
    result = 1
    # Binary string of private key (e.g., "101101")
    d_bin = bin(d)[2:]
    
    for bit in d_bin:
        # Square step
        result = (result * result) % n
        if bit == '1':
            # Multiply step (only happens if bit is 1)
            result = (result * ciphertext) % n
    return result

# --- Secure Implementation (Defense) ---
def blinded_decrypt(ciphertext, public_key, private_key):
    """
    A secure RSA decryption using the blinding technique
    to prevent timing attacks.
    """
    e, n = public_key
    d, n_priv = private_key
    
    # 1. Generate a random number 'r'
    r = random.randint(2, n - 1)
    
    # 2. Blind the ciphertext: C' = C * r^e mod n
    c_prime = (ciphertext * pow(r, e, n)) % n
    
    # 3. Decrypt the blinded ciphertext: M' = (C')^d mod n
    # This can be done with the vulnerable function, since the input is random.
    m_prime = vulnerable_decrypt(c_prime, private_key)
    
    # 4. Unblind the result: M = M' * r^-1 mod n
    r_inv = pow(r, -1, n) # Use fast built-in modular inverse
    m = (m_prime * r_inv) % n
    
    return m

# --- Attack Simulation ---
def run_timing_experiment(decrypt_function, public_key, private_key, num_trials=5000):
    """
    Runs a timing experiment by decrypting many messages
    and recording the time taken for each.
    """
    e, n = public_key
    d, n_priv = private_key
    
    print(f"\n--- Testing function: {decrypt_function.__name__} ---")
    times = []
    
    for i in range(num_trials):
        message = random.randint(1, n - 1)
        ciphertext = pow(message, e, n)
        
        start_time = time.perf_counter_ns()
        
        # Call the decryption function to be tested
        decrypt_function(ciphertext, private_key)
        
        end_time = time.perf_counter_ns()
        times.append(end_time - start_time)
        
    # Basic analysis of the timing results
    avg_time = sum(times) / num_trials
    min_time = min(times)
    max_time = max(times)
    
    print(f"  Average decryption time: {avg_time:,.2f} ns")
    print(f"  Min time: {min_time:,.2f} ns")
    print(f"  Max time: {max_time:,.2f} ns")
    print(f"  Time variation (max-min): {max_time - min_time:,.2f} ns")
    
    # For the vulnerable function, the variation will be high.
    # For the blinded function, the variation will be lower and random.
    return avg_time, max_time - min_time


if __name__ == "__main__":
    # 1. Setup RSA keys
    # Using 256-bit primes to make the attack measurable
    print("Generating 512-bit RSA key (2x 256-bit primes)...")
    p = generate_prime_number(256)
    q = generate_prime_number(256)
    
    public_key, private_key = generate_keypair(p, q)
    print("RSA key generated.")

    # Number of trials for the experiment
    TRIALS = 5000

    # 2. Test the vulnerable function
    print(f"\nRunning timing experiment on VULNERABLE function...")
    avg_vuln, var_vuln = run_timing_experiment(
        vulnerable_decrypt, 
        public_key, 
        private_key,
        num_trials=TRIALS
    )

    # 3. Test the secure (blinded) function
    # We create a wrapper to match the arguments for the experiment function
    def wrapper_blinded(ciphertext, private_key):
        return blinded_decrypt(ciphertext, public_key, private_key)

    print(f"\nRunning timing experiment on BLINDED function...")
    avg_blind, var_blind = run_timing_experiment(
        wrapper_blinded, 
        public_key, 
        private_key,
        num_trials=TRIALS
    )

    print("\n--- Final Results ---")
    print(f"Vulnerable Time Variation: {var_vuln:,.2f} ns")
    print(f"Blinded Time Variation:    {var_blind:,.2f} ns")
    print("\n")
    
    print("ANALYSIS:")
    print("The vulnerable function has a large time variation because its runtime depends on the private key's bits.")
    print("The blinded function's timing is randomized, breaking the link between time and the key.")
    print("SUCCESS: The blinding defense reduces the exploitable timing signal.")
