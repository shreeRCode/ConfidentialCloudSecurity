import os

def get_user_input():
    print("\n" + "="*60)
    print("Adaptive Cryptographic Framework")
    print("Choose an input method. Type 'exit' at any time to quit.")
    print("="*60)

    choice = input("Enter 'text' to type data directly or 'file' to encrypt a file: ").lower().strip()

    if choice == 'exit':
        return None, None, None

    data_bytes = None
    data_source = "Error"

    if choice == 'text':
        data_str = input("Enter the data to encrypt: ")
        if data_str.lower() == 'exit':
            return None, None, None
        data_bytes = data_str.encode('utf-8')
        data_source = "UserText"

    elif choice == 'file':
        file_path = input("Enter the path to the file: ")
        if file_path.lower() == 'exit':
            return None, None, None
        try:
            with open(file_path, 'rb') as f:
                data_bytes = f.read()
            data_source = os.path.basename(file_path)
        except FileNotFoundError:
            print(f"  ->  ERROR: The file was not found at '{file_path}'")
            return "Error", None, None
        except Exception as e:
            print(f"  ->  ERROR: Could not read the file. Reason: {e}")
            return "Error", None, None
    else:
        print("  -> ERROR: Invalid choice. Please enter 'text' or 'file'.")
        return "Error", None, None

    sensitivity = input("Enter the sensitivity level (high/medium/low): ")
    if sensitivity.lower() == 'exit':
        return None, None, None

    return data_source, data_bytes, sensitivity