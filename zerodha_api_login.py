"""
oauth_login_final.py

Purpose:
- Automate OAuth login for Kite Connect apps: open login URL, do credential + TOTP flow, capture request_token,
  exchange for access_token and save encrypted token.

Pre-reqs (in your virtualenv):
pip install kiteconnect selenium webdriver-manager python-dotenv pyotp cryptography

Files used:
- .env (API_KEY, API_SECRET, REDIRECT_URL, FERNET_KEY, HEADLESS, KEEP_BROWSER_MINUTES, etc.)
- accounts.csv (columns: user_id,password,totp_secret)
- token_manager.py (must implement save_encrypted_token(client_id, token))
- notify.py (optional, send_email function)

Security:
- Keep .env and accounts.csv private
- Use FERNET_KEY from a real secret store in production
"""

import os
import csv
import time
import logging
import traceback
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from datetime import datetime, timedelta

from dotenv import load_dotenv
import pyotp
from kiteconnect import KiteConnect

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, NoSuchElementException, ElementNotInteractableException, WebDriverException

# Optional helpers from your project
from token_manager import save_encrypted_token   # MUST exist
from notify import send_email                    # Optional: send notifications

# Load environment
load_dotenv()

API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
REDIRECT_URL = os.getenv("REDIRECT_URL", "http://localhost:8000/callback")
ACCOUNTS_CSV = os.getenv("ACCOUNTS_CSV", "accounts.csv")
HEADLESS = os.getenv("HEADLESS", "false").lower() in ("1", "true", "yes")
KEEP_BROWSER_MINUTES = int(os.getenv("KEEP_BROWSER_MINUTES", "0"))  # keep browser open for N minutes after login (0 = close immediately)
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Logging config
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "oauth_login_final.log"),
        logging.StreamHandler()
    ]
)

# ---------------- Utility helpers ----------------

def screenshot(driver, name_prefix="error"):
    ts = int(time.time())
    path = LOG_DIR / f"{name_prefix}_{ts}.png"
    try:
        driver.save_screenshot(str(path))
        logging.info("Screenshot saved: %s", path)
    except Exception as e:
        logging.warning("Failed to save screenshot: %s", e)
    return path

def read_accounts(file_path=ACCOUNTS_CSV):
    if not os.path.exists(file_path):
        logging.error("Accounts CSV not found: %s", file_path)
        return []
    rows = []
    with open(file_path, newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        for r in reader:
            uid = r.get("user_id") or r.get("userid") or r.get("user")
            pwd = r.get("password")
            totp = r.get("totp_secret") or r.get("totp") or r.get("secret")
            if not (uid and pwd and totp):
                logging.warning("Skipping incomplete row: %s", r)
                continue
            rows.append((uid.strip(), pwd.strip(), totp.strip()))
    return rows

# ---------------- WebDriver builder ----------------

def build_driver():
    """
    Build a Chrome WebDriver with webdriver-manager handling driver binary.
    """
    options = Options()
    options.add_argument("--window-size=1366,900")
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-popup-blocking")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    if HEADLESS:
        # modern headless
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
    # instantiate driver with autoinstalled binary
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(60)
    return driver

# ---------------- OTP field detection and entry ----------------

def find_otp_fields(driver, timeout=12):
    """
    Robustly find OTP input area.
    Returns: list of WebElement(s) (split boxes or single input). Empty list if not found.
    """
    end = time.time() + timeout
    while time.time() < end:
        try:
            # common single-field id
            els = driver.find_elements(By.ID, "totp")
            if els:
                el = els[0]
                if el.is_displayed() and el.is_enabled():
                    return [el]
        except Exception:
            pass

        try:
            els = driver.find_elements(By.ID, "pin")
            if els:
                el = els[0]
                if el.is_displayed() and el.is_enabled():
                    return [el]
        except Exception:
            pass

        # detect split single-char OTP boxes (maxlength=1)
        try:
            cand = driver.find_elements(By.XPATH, "//input[@maxlength='1' and ( @inputmode='numeric' or contains(@class,'otp') or contains(@class,'digit') )]")
            cand = [e for e in cand if e.is_displayed() and e.is_enabled()]
            if len(cand) >= 2:
                return cand
        except Exception:
            pass

        # fallback: numeric input or password input visible
        try:
            cand = driver.find_elements(By.XPATH, "//input[@inputmode='numeric' or @type='tel' or @type='number' or @type='password']")
            cand = [e for e in cand if e.is_displayed() and e.is_enabled()]
            if cand:
                return cand
        except Exception:
            pass

        time.sleep(0.4)
    return []

def enter_otp(driver, otp, fields):
    """
    Enter otp string into found fields.
    - If single field -> send full otp
    - If multiple -> send one char per field
    Uses ActionChains / click to make it more robust.
    Returns True if appears to have input successfully.
    """
    try:
        if not fields:
            return False
        actions = ActionChains(driver)
        if len(fields) == 1:
            fld = fields[0]
            # try JS set then confirm with keys
            try:
                driver.execute_script("arguments[0].focus(); arguments[0].value = arguments[1];", fld, otp)
            except Exception:
                pass
            try:
                fld.clear()
                fld.click()
            except Exception:
                pass
            fld.send_keys(otp)
            return True
        # split boxes
        for i, ch in enumerate(otp):
            if i >= len(fields):
                break
            fld = fields[i]
            try:
                driver.execute_script("arguments[0].focus();", fld)
            except Exception:
                pass
            try:
                fld.clear()
            except Exception:
                pass
            try:
                fld.click()
            except Exception:
                pass
            # small delay to mimic human typing
            fld.send_keys(ch)
            time.sleep(0.06)
        return True
    except Exception as e:
        logging.exception("Error entering OTP: %s", e)
        return False

# ---------------- wait for request_token redirect ----------------

def wait_for_request_token(driver, timeout=25):
    """
    Poll current_url until request_token= appears, return (request_token, status, final_url)
    """
    end = time.time() + timeout
    while time.time() < end:
        try:
            cur = driver.current_url
        except Exception:
            cur = ""
        if "request_token=" in cur:
            parsed = urlparse(cur)
            q = parse_qs(parsed.query)
            rt = q.get("request_token", [None])[0]
            status = q.get("status", [None])[0]
            return rt, status, cur
        time.sleep(0.5)
    return None, None, driver.current_url

# ---------------- main per-account flow ----------------

def perform_oauth_login(user_id, password, totp_secret):
    driver = None
    try:
        logging.info("=== Login start: %s ===", user_id)
        # make KiteConnect instance to build login url
        kite = KiteConnect(api_key=API_KEY)
        login_url = kite.login_url()  # includes api_key & redirect params
        logging.info("Login URL: %s", login_url)

        driver = build_driver()
        wait = WebDriverWait(driver, 25)

        # navigate to oauth login URL (so Kite will redirect to app redirect_url)
        driver.get(login_url)
        # fill userid
        uid_field = wait.until(EC.presence_of_element_located((By.ID, "userid")))
        uid_field.clear()
        uid_field.send_keys(user_id)
        # fill password
        pwd_field = driver.find_element(By.ID, "password")
        pwd_field.clear()
        pwd_field.send_keys(password)
        # click submit
        submit = driver.find_element(By.XPATH, "//button[@type='submit']")
        submit.click()
        logging.info("Submitted credentials")

        # small wait for next screen
        time.sleep(1.0)

        # find OTP fields
        fields = find_otp_fields(driver, timeout=18)
        if not fields:
            logging.error("❌ No OTP fields found for %s", user_id)
            screenshot(driver, f"no_otp_{user_id}")
            send_email(f"Kite OTP not found for {user_id}", f"Unable to find OTP input after credentials submission for {user_id}")
            return False

        # generate OTP
        try:
            otp = pyotp.TOTP(totp_secret).now()
            logging.info("Generated OTP: %s", otp)
        except Exception as e:
            logging.exception("Failed to generate OTP for %s: %s", user_id, e)
            return False

        # enter OTP (ActionChains friendly)
        ok = enter_otp(driver, otp, fields)
        if not ok:
            logging.error("❌ OTP entry failed for %s", user_id)
            screenshot(driver, f"otp_entry_fail_{user_id}")
            send_email(f"Kite OTP entry failed for {user_id}", f"OTP entry failed for {user_id}")
            return False

        # click Continue / Submit
        clicked = False
        try:
            # try a visible button with Continue text
            btn = driver.find_elements(By.XPATH, "//button[normalize-space()='Continue' or normalize-space()='CONTINUE' or normalize-space()='Continue ']")
            if btn:
                for b in btn:
                    try:
                        if b.is_displayed() and b.is_enabled():
                            b.click()
                            clicked = True
                            break
                    except Exception:
                        pass
        except Exception:
            pass
        if not clicked:
            # fallback: click first submit button in view
            try:
                btn = driver.find_element(By.XPATH, "//button[@type='submit']")
                btn.click()
                clicked = True
            except Exception:
                pass
        logging.info("TOTP submitted. Waiting for redirect... (clicked=%s)", clicked)

        # wait for request_token (redirect to your REDIRECT_URL)
        rt, status, final_url = wait_for_request_token(driver, timeout=30)
        if not rt:
            # maybe no redirect but dashboard loaded (Zerodha behaviour can differ).
            # Try detect logged-in state by presence of profile / positions text
            try:
                WebDriverWait(driver, 6).until(EC.presence_of_element_located((By.XPATH, "//*[contains(@class,'profile') or contains(@class,'user-id') or contains(text(),'Positions') or contains(text(),'Holdings')]")))
                logging.info("Login appears successful for %s (dashboard loaded). No request_token in URL.", user_id)
                # If you need request_token for API, this means the oauth flow did not redirect to your redirect URL (maybe your app settings mismatch).
                # Save screenshot and return success/failure depending on your need.
                screenshot(driver, f"logged_in_no_request_{user_id}")
                return True
            except Exception:
                logging.error("❌ No request_token found and dashboard not detected. Final URL: %s", final_url)
                screenshot(driver, f"no_request_token_{user_id}")
                send_email(f"Kite login failed for {user_id}", f"No request_token captured. Final URL: {final_url}")
                return False

        logging.info("Captured request_token for %s (status=%s) -> %s", user_id, status, rt)

        # Exchange request_token for access_token (server-side)
        kite2 = KiteConnect(api_key=API_KEY)
        try:
            data = kite2.generate_session(rt, api_secret=API_SECRET)
        except Exception as ex:
            logging.exception("generate_session failed: %s", ex)
            screenshot(driver, f"generate_session_{user_id}")
            send_email(f"Kite generate_session failed for {user_id}", f"Error: {ex}")
            return False

        access_token = data.get("access_token")
        if not access_token:
            logging.error("generate_session returned no access_token for %s: %s", user_id, data)
            screenshot(driver, f"no_access_token_{user_id}")
            send_email(f"Kite token missing for {user_id}", f"generate_session returned: {data}")
            return False

        # Save encrypted token
        try:
            save_encrypted_token(user_id, access_token)
            logging.info("Access token saved (encrypted) for %s", user_id)
            send_email(f"Kite token updated for {user_id}", f"Access token refreshed and saved for {user_id}")
        except Exception as e:
            logging.exception("Failed to save token for %s: %s", user_id, e)
            return False

        # Optionally keep browser open for heartbeat if configured
        if KEEP_BROWSER_MINUTES > 0:
            expiry = datetime.utcnow() + timedelta(minutes=KEEP_BROWSER_MINUTES)
            logging.info("Keeping browser open for %d minutes until %s UTC", KEEP_BROWSER_MINUTES, expiry.isoformat())
            try:
                while datetime.utcnow() < expiry:
                    # perform lightweight interaction every few minutes to keep session alive
                    try:
                        driver.execute_script("void(0);")
                        # or simple refresh small area if needed
                    except Exception:
                        pass
                    time.sleep(30)
            except KeyboardInterrupt:
                logging.info("Interrupted while keeping browser open")
        return True

    except WebDriverException as wde:
        logging.exception("WebDriver exception for %s: %s", user_id, wde)
        if driver:
            try:
                screenshot(driver, f"webdriver_exc_{user_id}")
            except Exception:
                pass
        return False
    except Exception as e:
        logging.exception("Unhandled error for %s: %s", user_id, e)
        if driver:
            try:
                screenshot(driver, f"exception_{user_id}")
            except Exception:
                pass
        return False
    finally:
        # cleanup: ensure driver quit
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

# ---------------- main ----------------

def main():
    if not API_KEY or not API_SECRET:
        logging.error("API_KEY or API_SECRET missing in environment (.env)")
        return

    accounts = read_accounts()
    logging.info("Loaded %d accounts", len(accounts))
    for uid, pwd, totp in accounts:
        try:
            ok = perform_oauth_login(uid, pwd, totp)
            logging.info("Result for %s: %s", uid, ok)
        except KeyboardInterrupt:
            logging.info("Interrupted by user")
            break
        except Exception:
            logging.exception("Unhandled error in main loop for %s", uid)
        # brief pause between accounts
        time.sleep(4)

if __name__ == "__main__":
    main()
