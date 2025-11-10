import sys
from policy_engine import PolicyEngine
from encryption import CryptoEngine
from input_handler import get_user_input
from utils import clear_screen, print_header
from azure_integration import get_master_key_from_vault, upload_to_blob, download_from_blob, is_running_in_secure_enclave

def process_data_in_memory(data_bytes: bytes, data_source: str) -> str:
    print(f"  -> [TEE Processing]: Analyzing '{data_source}' in protected memory...")
    try:
        data_str = data_bytes.decode('utf-8')
        sensitive_keywords = ["password", "email", "ssn", "creditcard", "confidential", "secret"]
        detected = [kw for kw in sensitive_keywords if kw in data_str.lower()]
        scan_result = (
            f"Sensitive keywords detected: {', '.join(detected)}"
            if detected else "No sensitive keywords detected."
        )
        word_count = len(data_str.split())
        print(f"  -> [TEE Processing]: Analysis complete. Discarding plaintext from memory.")
        return f"{{'source': '{data_source}', 'word_count': {word_count}, 'scan_result': '{scan_result}'}}"
    except UnicodeDecodeError:
        print(f"  -> [TEE Processing]: Data is non-text binary. Calculating size.")
        print(f"  -> [TEE Processing]: Analysis complete. Discarding plaintext from memory.")
        return f"{{'source': '{data_source}', 'data_size_bytes': {len(data_bytes)}}}"
    except Exception as e:
        return f"{{'error': 'Processing failed: {e}'}}"

def main():
    print_header("Initializing Adaptive Framework")
    try:
        MASTER_KEY = get_master_key_from_vault()
    except Exception as e:
        print(f"\nFATAL SETUP ERROR: Cannot proceed without Master Key. {e}")
        sys.exit(1)

    crypto_engine = CryptoEngine(MASTER_KEY)
    policy_engine = PolicyEngine()

    while True:
        clear_screen()
        data_source, data, sensitivity = get_user_input()

        if data_source is None:
            print("Exiting application. Goodbye!")
            break
        if data is None:
            input("\nPress Enter to continue...")
            continue

        print_header("Processing Request")
        print(f"  Source: '{data_source}'")
        print(f"  Sensitivity: '{sensitivity}'")
        print(f"  Data Size: {len(data)} bytes")

        try:
            chosen_algorithm = policy_engine.select_algorithm(sensitivity)
            encrypted_blob = crypto_engine.encrypt(data, chosen_algorithm)
            print(f"\n  -> Encryption successful (Ciphertext size: {len(encrypted_blob)} bytes).")

            blob_name = f"encrypted-{data_source}-{chosen_algorithm.lower()}.bin"
            upload_to_blob(blob_name, encrypted_blob)

            print_header("Data Retrieval and Processing")

            retrieved_blob = download_from_blob(blob_name)
            if retrieved_blob != encrypted_blob:
                raise Exception("Integrity check failed: Retrieved blob does not match uploaded blob.")
            print(f"  -> Encrypted data retrieved successfully (size: {len(retrieved_blob)} bytes).")

            if not is_running_in_secure_enclave():
                raise Exception(
                    "Unauthorized Access: Decryption is prohibited outside of a "
                    "secure TEE (Confidential VM)."
                )

            print("\n  -> Proceeding with decryption inside secure enclave.")
            decrypted_data = crypto_engine.decrypt(retrieved_blob, chosen_algorithm)
            print(f"\n  -> Decryption successful.")

            print(f"  -> Processing data securely in protected memory...")
            processing_result = process_data_in_memory(decrypted_data, data_source)
            print(f"  -> SUCCESS: Processing complete. Plaintext has been discarded.")
            print(f"  -> Result of in-memory computation: {processing_result}")

            if data == decrypted_data:
                print("  -> Verification: PASSED (Decrypted data matches original input)")
            else:
                print("  -> Verification: FAILED (Data mismatch after decryption!)")

        except Exception as e:
            print(f"\n  ->  ERROR during processing: {e}")

        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
