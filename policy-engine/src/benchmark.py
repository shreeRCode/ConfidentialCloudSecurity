import time
import os
import matplotlib.pyplot as plt

# Create benchmarks folder if it doesn't exist
os.makedirs('benchmarks', exist_ok=True)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from azure_integration import get_master_key_from_vault, upload_to_blob, download_from_blob
from encryption import CryptoEngine

def benchmark_encryption_time_vs_payload_size(master_key: bytes, algorithms: list, payload_sizes_kb: list):
    """
    Benchmark encryption time vs payload size for different algorithms.
    """
    crypto_engine = CryptoEngine(master_key)
    results = {algo: [] for algo in algorithms}

    for size_kb in payload_sizes_kb:
        size_bytes = size_kb * 1024
        plaintext = os.urandom(size_bytes)
        for algo in algorithms:
            start_time = time.time()
            ciphertext = crypto_engine.encrypt(plaintext, algo)
            end_time = time.time()
            encryption_time_ms = (end_time - start_time) * 1000
            results[algo].append(encryption_time_ms)
            print(f"  -> {algo}: {size_kb} KB -> {encryption_time_ms:.2f} ms")

    # Plot the results
    plt.figure(figsize=(10, 6))
    for algo, times in results.items():
        plt.plot(payload_sizes_kb, times, label=algo, marker='o')
    plt.xlabel('Payload Size (KB)')
    plt.ylabel('Encryption Time (ms)')
    plt.title('Encryption Time vs Payload Size')
    plt.legend()
    plt.grid(True)
    plt.savefig('benchmarks/encryption_time_vs_payload.png')
    plt.show()
    print("  -> Graph saved as 'benchmarks/encryption_time_vs_payload.png'")

def benchmark_algorithm_throughput(master_key: bytes, algorithms: list, payload_size_mb: int = 1):
    """
    Benchmark throughput (MB/s) for different algorithms.
    """
    crypto_engine = CryptoEngine(master_key)
    size_bytes = payload_size_mb * 1024 * 1024
    plaintext = os.urandom(size_bytes)
    results = {}

    for algo in algorithms:
        start_time = time.time()
        ciphertext = crypto_engine.encrypt(plaintext, algo)
        end_time = time.time()
        total_time_s = end_time - start_time
        throughput_mbs = (size_bytes / (1024 * 1024)) / total_time_s
        results[algo] = throughput_mbs
        print(f"  -> {algo}: {throughput_mbs:.2f} MB/s")

    # Plot the results
    plt.figure(figsize=(8, 5))
    plt.bar(results.keys(), results.values(), color=['blue', 'green', 'red'])
    plt.xlabel('Algorithm')
    plt.ylabel('Throughput (MB/s)')
    plt.title('Algorithm Throughput Comparison')
    plt.grid(axis='y')
    plt.savefig('benchmarks/algorithm_throughput.png')
    plt.show()
    print("  -> Graph saved as 'benchmarks/algorithm_throughput.png'")

def benchmark_key_vault_latency(operations: list, num_trials: int = 10):
    """
    Benchmark latency for Key Vault operations.
    """
    results = {op: [] for op in operations}

    for op in operations:
        for _ in range(num_trials):
            start_time = time.time()
            if op == "Token Retrieval":
                # Simulate token retrieval (using get_master_key_from_vault as proxy)
                try:
                    get_master_key_from_vault()
                except Exception:
                    pass  # Ignore errors for benchmarking
            elif op == "Key Fetch":
                # Simulate key fetch (same as above)
                try:
                    get_master_key_from_vault()
                except Exception:
                    pass
            elif op == "Blob Upload":
                # Simulate blob upload
                try:
                    upload_to_blob("benchmark-test.bin", b"test data")
                except Exception:
                    pass
            end_time = time.time()
            latency_ms = (end_time - start_time) * 1000
            results[op].append(latency_ms)

    # Calculate averages
    avg_results = {op: sum(times) / len(times) for op, times in results.items()}

    # Plot the results
    plt.figure(figsize=(8, 5))
    plt.bar(avg_results.keys(), avg_results.values(), color='purple')
    plt.xlabel('Operation Type')
    plt.ylabel('Average Time (ms)')
    plt.title('Key Vault Latency')
    plt.grid(axis='y')
    plt.savefig('benchmarks/key_vault_latency.png')
    plt.show()
    print("  -> Graph saved as 'benchmarks/key_vault_latency.png'")

def benchmark_policy_engine_accuracy(policy_engine, test_cases: list):
    """
    Benchmark policy engine accuracy.
    """
    correct = 0
    misclassifications = 0
    for sensitivity, expected_algo in test_cases:
        try:
            selected_algo = policy_engine.select_algorithm(sensitivity)
            if selected_algo == expected_algo:
                correct += 1
            else:
                misclassifications += 1
        except ValueError:
            misclassifications += 1

    accuracy = (correct / len(test_cases)) * 100
    print(f"  -> Policy Engine Accuracy: {accuracy:.2f}%")
    print(f"  -> Misclassifications: {misclassifications}")

    # Plot as bar graph
    plt.figure(figsize=(6, 4))
    plt.bar(['Accuracy (%)', 'Misclassifications'], [accuracy, misclassifications], color=['green', 'red'])
    plt.ylabel('Value')
    plt.title('Policy Engine Accuracy')
    plt.grid(axis='y')
    plt.savefig('benchmarks/policy_engine_accuracy.png')
    plt.show()
    print("  -> Graph saved as 'benchmarks/policy_engine_accuracy.png'")

def benchmark_security_enforcement_trials(master_key: bytes, num_trials: int = 10):
    """
    Benchmark security enforcement trials.
    """
    from azure_integration import is_running_in_secure_enclave

    success_count = 0
    blocked_outside_tee = 0

    crypto_engine = CryptoEngine(master_key)
    plaintext = b"test data"
    algorithm = "AES-256-GCM"

    for _ in range(num_trials):
        try:
            ciphertext = crypto_engine.encrypt(plaintext, algorithm)
            # Attempt decryption
            if is_running_in_secure_enclave():
                crypto_engine.decrypt(ciphertext, algorithm)
                success_count += 1
            else:
                # This should fail
                try:
                    crypto_engine.decrypt(ciphertext, algorithm)
                except Exception:
                    blocked_outside_tee += 1
        except Exception:
            pass  # Encryption or other errors

    success_rate = (success_count / num_trials) * 100
    blocked_rate = (blocked_outside_tee / num_trials) * 100

    print(f"  -> Security Enforcement Trials:")
    print(f"     - Success Rate: {success_rate:.2f}%")
    print(f"     - Blocked Outside TEE: {blocked_rate:.2f}%")

    # Display as table (since matplotlib table is complex, print to console)
    print("\n  -> Trials Table:")
    print(f"    | Trials | Success (%) | Blocked Outside TEE |")
    print(f"    |--------|-------------|---------------------|")
    print(f"    | {num_trials}     | {success_rate:.2f}       | {blocked_rate:.2f}                |")

def run_all_benchmarks():
    """
    Run all benchmarks.
    """
    print("Starting Cryptographic Framework Benchmarks...")

    try:
        master_key = get_master_key_from_vault()
    except Exception as e:
        print(f"Cannot run benchmarks without Master Key: {e}")
        return

    algorithms = ["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"]
    payload_sizes_kb = [1, 10, 50, 100, 500, 1000]  # Up to 1 MB

    print("\n1. Benchmarking Encryption Time vs Payload Size...")
    benchmark_encryption_time_vs_payload_size(master_key, algorithms, payload_sizes_kb)

    print("\n2. Benchmarking Algorithm Throughput...")
    benchmark_algorithm_throughput(master_key, algorithms)

    print("\n3. Benchmarking Key Vault Latency...")
    operations = ["Token Retrieval", "Key Fetch", "Blob Upload"]
    benchmark_key_vault_latency(operations)

    print("\n4. Benchmarking Policy Engine Accuracy...")
    from policy_engine import PolicyEngine
    policy_engine = PolicyEngine()
    test_cases = [
        ("high", "AES-256-GCM"),
        ("medium", "AES-128-GCM"),
        ("low", "ChaCha20-Poly1305"),
        ("High", "AES-256-GCM"),  # Case insensitive
        ("invalid", None)  # Should raise error
    ]
    benchmark_policy_engine_accuracy(policy_engine, test_cases)

    print("\n5. Benchmarking Security Enforcement Trials...")
    benchmark_security_enforcement_trials(master_key)

    print("\nAll benchmarks completed. Graphs saved in 'benchmarks/' folder.")

if __name__ == "__main__":
    run_all_benchmarks()
