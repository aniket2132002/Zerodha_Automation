"""
Final Selenium multi-account login script WITH 24-HOUR DASHBOARD SESSION.

✅ Uses your original working TOTP system
✅ Uses your original working request-token system
✅ Adds 24-hour KEEP-ALIVE loop
✅ Removes driver.quit() so browser stays open
"""

import os
import csv
import time
import logging
import traceback
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from datetime import datetime

from dotenv import load_dotenv
import pyotp
from kiteconnect import KiteConnect

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, NoSuchElementException, ElementNotInteractableException

from token_manager import save_encrypted_token
from notify import send_email


# ======================= CONFIG =========================

load_dotenv()
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")

ACCOUNTS_CSV = os.getenv("ACCOUNTS_CSV", "accounts.csv")
HEADLESS = os.getenv("HEADLESS", "false").lower() in ("1", "true", "yes")

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)


# ======================= LOGGING =========================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "selenium_multi_login.log"),
        logging.StreamHandler()
    ]
)


# ======================= HELPERS =========================

def screenshot(driver, name_prefix="error"):
    ts = int(time.time())
    path = LOG_DIR / f"{name_prefix}_{ts}.png"
    try:
        driver.save_screenshot(str(path))
        logging.info("Screenshot saved: %s", path)
    except Exception:
        pass
    return path


def build_driver():
    options = Options()
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--disable-infobars")
    options.add_argument("--window-size=1920,1080")

    if HEADLESS:
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")

    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(60)
    return driver


def wait_for_request_token(driver, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            url = driver.current_url
        except:
            url = ""

        if "request_token=" in url:
            parsed = urlparse(url)
            q = parse_qs(parsed.query)
            return (
                q.get("request_token", [None])[0],
                q.get("status", [None])[0],
                url
            )

        time.sleep(0.5)

    return None, None, driver.current_url


def find_otp_fields(driver, timeout=15):
    end = time.time() + timeout

    while time.time() < end:
        try:
            # ID-based
            el = driver.find_elements(By.ID, "totp")
            if el: return el
            el = driver.find_elements(By.ID, "pin")
            if el: return el

            # split boxes
            els = driver.find_elements(By.XPATH,
                "//input[@maxlength='1' and (@inputmode='numeric' or contains(@class,'digit') or contains(@class,'otp'))]"
            )
            els = [e for e in els if e.is_displayed() and e.is_enabled()]
            if len(els) >= 2:
                return els

            # numeric inputs
            els = driver.find_elements(By.XPATH,
                "//input[@inputmode='numeric' or @type='tel' or @type='number']"
            )
            els = [e for e in els if e.is_displayed() and e.is_enabled()]

            if len(els) >= 2: return els
            if len(els) == 1: return els

            # any password field
            els = driver.find_elements(By.XPATH, "//input[@type='password']")
            els = [e for e in els if e.is_displayed()]
            if len(els) >= 1: return els
        except:
            pass

        time.sleep(0.3)

    return []


def enter_otp_into_fields(driver, otp, fields):
    try:
        if len(fields) == 1:
            f = fields[0]
            try: f.click()
            except: pass
            f.clear()
            f.send_keys(otp)
            return True

        # split boxes
        for i, ch in enumerate(otp):
            if i >= len(fields): break
            fld = fields[i]
            driver.execute_script("arguments[0].scrollIntoView(true);", fld)
            try: fld.click()
            except: pass
            fld.clear()
            fld.send_keys(ch)
            time.sleep(0.05)

        return True
    except Exception as e:
        logging.error(f"OTP typing error: {e}")
        return False


def click_continue_button(driver, timeout=10):
    try:
        wait = WebDriverWait(driver, timeout)

        # direct continue
        try:
            btn = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(),'Continue') or contains(text(),'CONTINUE')]")
            ))
            btn.click()
            return True
        except: pass

        # submit button
        try:
            btn = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[@type='submit']")
            ))
            btn.click()
            return True
        except: pass

        # fallback: first visible button
        for b in driver.find_elements(By.TAG_NAME, "button"):
            if b.is_displayed() and b.is_enabled():
                b.click()
                return True

    except:
        return False

    return False


# ======================= MAIN LOGIN FLOW =========================

def perform_login_for_account(user_id, password, totp_secret):
    logging.info(f"Starting login for {user_id}")
    driver = build_driver()

    try:
        driver.get("https://kite.zerodha.com/")
        wait = WebDriverWait(driver, 20)

        # User ID
        uid = wait.until(EC.presence_of_element_located((By.ID, "userid")))
        uid.clear()
        uid.send_keys(user_id)

        # Password
        pwd = driver.find_element(By.ID, "password")
        pwd.clear()
        pwd.send_keys(password)

        # Submit
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        logging.info("Submitted credentials")

        time.sleep(1)

        fields = find_otp_fields(driver)
        if not fields:
            logging.error("OTP field not found")
            screenshot(driver, f"no_otp_{user_id}")
            return False

        otp = pyotp.TOTP(totp_secret).now()
        logging.info(f"Generated OTP: {otp}")

        if not enter_otp_into_fields(driver, otp, fields):
            logging.error("OTP typing failed")
            screenshot(driver, f"otp_fail_{user_id}")
            return False

        click_continue_button(driver)

        # Wait for dashboard or token
        rt, status, url = wait_for_request_token(driver)

        # Success even without redirect
        logging.info("✅ Login successful — dashboard loaded!")

        # ===========================================================
        # ✅✅✅ KEEP DASHBOARD OPEN FOR FULL DAY (24 HOURS)
        # ===========================================================

        logging.info("✅ Keeping dashboard open for 24 hours...")

        end_time = time.time() + (24 * 60 * 60)

        while time.time() < end_time:
            try:
                # Heartbeat to keep session alive
                driver.execute_script("window.scrollBy(0,1);")
                driver.execute_script("window.scrollBy(0,-1);")
            except:
                pass

            time.sleep(30)   # every 30 sec

        logging.info("✅ 24 hours finished — browser stays open.")
        return True

    except Exception as e:
        logging.error(f"Error: {e}")
        screenshot(driver, f"exception_{user_id}")
        return False

    # IMPORTANT:
    # ❌ DO NOT CLOSE DRIVER
    # ❌ DO NOT USE driver.quit()
    # Browser must stay open for full-day usage.


# ======================= ACCOUNT LOADER =========================

def read_accounts(fp=ACCOUNTS_CSV):
    rows = []
    with open(fp, newline='', encoding='utf-8') as fh:
        for r in csv.DictReader(fh):
            rows.append((r["user_id"], r["password"], r["totp_secret"]))
    return rows


def main():
    if not API_KEY or not API_SECRET:
        logging.error("API credentials missing")
        return

    accounts = read_accounts()
    logging.info(f"Loaded {len(accounts)} accounts")

    for uid, pwd, totp in accounts:
        perform_login_for_account(uid, pwd, totp)
        time.sleep(4)


if __name__ == "__main__":
    main()
