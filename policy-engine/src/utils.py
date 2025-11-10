import os
import platform

def clear_screen():
    system_os = platform.system()
    if system_os == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def print_header(title: str):
    print("\n" + "="*60)
    print(f"{title.center(60)}")
    print("="*60)
