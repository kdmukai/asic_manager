# ASIC Manager

## Installation
Create virtualenv and install python dependencies
```
virtualenv .env
pip install -r requirements.txt
```

Customize your settings file:
```
# in src/settings.conf:
[ASIC]
IP_ADDRESS = 192.168.1.232
MAX_FREQ = 450
MIN_FREQ = 50
FREQ_STEP = 50
MAX_ELECTRICITY_PRICE = 8.0
RESUME_AFTER = 3
```
