# ASIC Manager

Dynamically controls a home miner based on user-configurable thresholds for:
* Current price of electricity
* Current chip temp

Built specifically for:
* Single board S19j Pro (with or without Loki)
* APW3 or APW12 psu
* External cooling (not using case fans)
* vnish in manual voltage + chip freq mode (no presets)
* ComEd real-time pricing customer

If you're using the case fans, they should be able to modulate the chip temps for you. I only use external inline fans so the temp control is up to me and this script.

This will probably work for other builds as long as you're running vnish and `pyasic` can talk to it.

Rough starting points in vnish:
* APW12: 13.0V
* APW3: modded or not, ideally measure the actual output and use that value (e.g. 12.6V).
* Max chip freq: Around 400 MHz to 550 MHz, depending on how effective your cooling is.


### Installation
```
# Create a python virtualenv
python3 -m venv .env

# Activate the virtualenv
source .env/bin/activate

# Clone the repo
git clone https://github.com/kdmukai/asic_manager.git

# Install python dependencies
cd asic_manager
pip install -r requirements.txt
```


### Customize your settings file:
```
nano src/settings.conf

# src/settings.conf:
[ASIC]
IP_ADDRESS = 192.168.1.232
MAX_FREQ = 450
MIN_FREQ = 50
FREQ_STEP = 50
MAX_ELECTRICITY_PRICE = 8.0
RESUME_AFTER = 3
MAX_TEMP = 80
RESUME_AT_TEMP = 76
```


### Run the script every minute
Set up a cron job for the script. Configure it to run every minute.
```
crontab -e

# in the cron editor, customize to your directories, etc.
* * * * * /root/.env/bin/python /root/asic_manager/src/main.py --settings /root/asic_manager/src/settings.conf >> /root/out.log 2>&1
```
