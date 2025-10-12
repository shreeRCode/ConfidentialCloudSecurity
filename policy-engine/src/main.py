import os
from policy_engine import PolicyEngine
from encryption import CryptoEngine
from input_handler import get_user_input

def main():
    # --- SETUP ---
    MASTER_KEY = os.urandom(32)
    crypto_engine = CryptoEngine(MASTER_KEY)
    policy_engine = PolicyEngine()

    # --- INTERACTIVE LOOP ---
    while True:
        data_source, data, sensitivity = get_user_input()

        # Handle exit condition
        if data_source is None:
            print("Exiting application. Goodbye!")
            break

        # Handle input errors (e.g., file not found)
        if data is None:
            continue # Skip to the next loop iteration and ask for input again

        print("-" * 60)
        print(f"Processing data from source: '{data_source}' with sensitivity: '{sensitivity}'")

        try:
            # 1. Policy Engine makes a decision
            chosen_algorithm = policy_engine.select_algorithm(sensitivity)

            # 2. Crypto Engine encrypts the data
            encrypted_blob = crypto_engine.encrypt(data, chosen_algorithm)
            print(f"  -> Encryption successful.")

            # Save the encrypted content to a new file
            output_filename = f"encrypted_{data_source}"
            with open(output_filename, 'wb') as f:
                f.write(encrypted_blob)
            print(f"  -> Encrypted content saved to: '{output_filename}'")

            # 3. Crypto Engine decrypts for verification
            decrypted_data = crypto_engine.decrypt(encrypted_blob, chosen_algorithm)
            print(f"  -> Decryption successful.")

            # 4. Verify integrity
            if data == decrypted_data:
                print("  ->  SUCCESS: Decrypted data matches the original content.")
                # Save the decrypted content to another file for manual verification
                decrypted_filename = f"decrypted_{data_source}"
                with open(decrypted_filename, 'wb') as f:
                    f.write(decrypted_data)
                print(f"  -> Decrypted content verified and saved to: '{decrypted_filename}'")
            else:
                print("  ->  FAILURE: Data mismatch after decryption!")

        except (ValueError, Exception) as e:
            print(f"  ->  ERROR during processing: {e}")
        print("-" * 60)

if __name__ == "__main__":
    main()