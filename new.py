from kiteconnect import KiteConnect
import os

API_KEY = "3dhuld48p6ccukga"
kite = KiteConnect(api_key=API_KEY)

print(kite.login_url())
