import random
import time
import io
import contextlib

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
    a_private = generate_private_key()
    a_public = generate_public_key(a_private)
    print(f"Ana's private: {a_private}, public: {a_public}")

    b_private = generate_private_key()
    b_public = generate_public_key(b_private)
    print(f"Phara's private: {b_private}, public: {b_public}")

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
    a_private = generate_private_key()
    a_public = generate_public_key(a_private)
    print(f"Ana's private: {a_private}, public: {a_public}")

    b_private = generate_private_key()
    b_public = generate_public_key(b_private)
    print(f"Phara's private: {b_private}, public: {b_public}")
    
    m_private = generate_private_key()
    m_public = generate_public_key(m_private)
    print(f"Doomfist's private: {m_private}, public: {m_public}")

    print("\nDoomfist intercepts and replaces the public keys...")
    
    s_ana = get_shared_secret(m_public, a_private)
    s_phara = get_shared_secret(m_public, b_private)
    
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
    
    print("\nGenerating RSA keys for Ana and Phara...")
    p, q = 61, 53
    a_rsa_pub, a_rsa_priv = generate_keypair(p, q)
    p, q = 67, 71
    b_rsa_pub, b_rsa_priv = generate_keypair(p, q)
    
    def sign(message, private_key):
        d, n = private_key
        return pow(message, d, n)

    def verify(message, signature, public_key):
        e, n = public_key
        decrypted_sig = pow(signature, e, n)
        return message == decrypted_sig

    a_private = generate_private_key()
    a_public = generate_public_key(a_private)
    a_sig = sign(a_public, a_rsa_priv)
    
    b_private = generate_private_key()
    b_public = generate_public_key(b_private)
    b_sig = sign(b_public, b_rsa_priv)
    
    m_private = generate_private_key()
    m_public = generate_public_key(m_private)
    m_fake_sig = 12345 
    
    print("\nDoomfist tries to substitute a fake key and signature...")
    
    if not verify(m_public, m_fake_sig, a_rsa_pub):
        print("Phara: Signature verification FAILED. Attack detected.")
    else:
        print("Phara: Signature OK.")
        
    if not verify(m_public, m_fake_sig, b_rsa_pub):
        print("Ana: Signature verification FAILED. Attack detected.")
    else:
        print("Ana: Signature OK.")

    print("\nAna and Phara exchange their real, signed keys.")
    phara_verifies_ana = verify(a_public, a_sig, a_rsa_pub)
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
    # 1. Run standard simulations
    simulate_normal_exchange()
    simulate_mitm_attack()
    simulate_authenticated_exchange()

    # 2. Performance Evaluation & Plotting
    print("--- Generating Performance Benchmark ---")
    benchmark_runs = 50
    
    start_time = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()): 
        for _ in range(benchmark_runs):
            simulate_normal_exchange()
    end_time = time.perf_counter()
    avg_normal_time = (end_time - start_time) / benchmark_runs

    start_time = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        for _ in range(benchmark_runs):
            simulate_authenticated_exchange()
    end_time = time.perf_counter()
    avg_auth_time = (end_time - start_time) / benchmark_runs

    print(f"Average Normal D-H Time: {avg_normal_time:.6f} s")
    print(f"Average Auth D-H Time:   {avg_auth_time:.6f} s")
    print(f"Overhead Factor: {avg_auth_time/avg_normal_time:.2f}x")

    # --- Plotting Section (Safe Import) ---
    try:
        import matplotlib.pyplot as plt
        print("\n[Optional] matplotlib found. Generating Performance Chart...")
        
        labels = ['Normal D-H', 'Authenticated D-H']
        times = [avg_normal_time, avg_auth_time]
        
        plt.figure(figsize=(8, 6))
        
        # 定义颜色
        colors = ['#4285F4', '#F4B400'] # 谷歌蓝和谷歌黄，比较好看
        bars = plt.bar(labels, times, color=colors)
        
        plt.title('Performance Overhead: Security vs. Speed')
        plt.ylabel('Average Execution Time (seconds)')
        
        # 优化Y轴刻度，使用科学计数法，避免 0.0000
        plt.ticklabel_format(axis='y', style='sci', scilimits=(0,0))
        
        # Add value text on bars (Fixed: Convert to Microseconds for display)
        for bar in bars:
            yval = bar.get_height()
            # 修改核心：yval * 1,000,000 转换为微秒，并保留2位小数
            display_text = f'{yval * 1_000_000:.2f} $\mu$s' 
            plt.text(bar.get_x() + bar.get_width()/2, yval, display_text, va='bottom', ha='center', fontsize=12, fontweight='bold')

        plt.savefig('dh_performance_chart.png')
        print("Chart saved as 'dh_performance_chart.png'.")
    except ImportError:
        print("\n[Note] matplotlib not found. Skipping plot generation.")