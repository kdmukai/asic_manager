"""
    Start/Stop mining on an S9 running Braiins OS
"""
import requests
from pyvirtualdisplay import Display
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By


class BraiinsS9:
    def __init__(self, ip_address="192.168.1.112", username="root", password="admin"):
        """
        Set up a logged in requests.Session for status calls.

        Set up a logged in webdriver.Chrome headless instance to alter power level
        """
        self.ip_address = ip_address
        self.session = requests.Session()
        data = dict(luci_username=username, luci_password=password)
        res = self.session.post(f"http://{ip_address}/cgi-bin/luci/", data=data)
        if res.status_code != 200:
            raise Exception(f"ERROR: status_code: {res.status_code}")

        self.display = Display(visible=0, size=(1024, 768))
        self.display.start()
        self.service = Service('/usr/lib/chromium-browser/chromedriver')
        self.driver = webdriver.Chrome(service=self.service)
        self.driver.get(f"http://{ip_address}/cgi-bin/luci")

        el_username = self.driver.find_element(By.NAME, "luci_username")
        el_username.clear()
        el_username.send_keys(username)
        el_password = self.driver.find_element(By.NAME, "luci_password")
        el_password.clear()
        el_password.send_keys(password)
        self.driver.find_element(By.XPATH, "//input[@type='submit']").click()


    def quit(self):
        self.driver.quit()
        self.service.stop()
        self.display.stop()


    def __del__(self):
        self.quit()


    def build_mining_config(self, board_1: bool = True, board_2: bool= True, board_3: bool = True):
        self.driver.get(f"http://{self.ip_address}/cgi-bin/luci/admin/miner/config")

        speed = self.driver.find_element(By.NAME, 'speed')
        if speed is not None:
            speed = speed.get_attribute("value")
            if speed == '':
                speed = 20
            else:
                speed = int(speed)

        return {
            "data":{
                "hash_chain":{
                    "6":{
                        "enabled": board_1
                    },
                    "7":{
                        "enabled": board_2
                    },
                    "8":{
                        "enabled": board_3
                    }
                },
                "temp_control":{
                    "target_temp": int(self.driver.find_element(By.NAME, 'target_temp').get_attribute("value")),
                    "hot_temp": int(self.driver.find_element(By.NAME, 'hot_temp').get_attribute("value")),
                    "dangerous_temp": int(self.driver.find_element(By.NAME, 'dangerous_temp').get_attribute("value"))
                },
                "fan_control":{
                    "speed": speed,
                    "min_fans": int(self.driver.find_element(By.NAME, 'min_fans').get_attribute("value")) if self.driver.find_element(By.NAME, 'min_fans').get_attribute("value") else None
                },
                "group":[
                    {
                        "name": self.driver.find_element(By.NAME, 'name').get_attribute("value"),
                        "pool":[
                            {
                                "enabled": True,
                                "url": self.driver.find_element(By.NAME, 'url').get_attribute("value"),
                                "user": self.driver.find_element(By.NAME, 'user').get_attribute("value"),
                                "password": self.driver.find_element(By.NAME, 'password').get_attribute("value")
                            }
                        ]
                    }
                ],
                "autotuning":{
                    # "enabled": False,   # Assume we've already let autotune run its full course
                    "enabled": True,
                    "psu_power_limit": int(self.driver.find_element(By.NAME, 'psu_power_limit').get_attribute("value"))
                },
                "power_scaling":{
                    "enabled": True,
                    "power_step": int(self.driver.find_element(By.NAME, 'power_step').get_attribute("value"))
                }
            }
        }


    @property
    def is_mining(self):
        res = self.session.get(f"http://{self.ip_address}/cgi-bin/luci/admin/miner/api_status/")
        cur_hashrate = res.json()["summary"][0]["SUMMARY"][0]["MHS 5s"]
        return cur_hashrate > 0.0


    def start_mining(self, board_1: bool = True, board_2: bool= True, board_3: bool = True):
        """ Enable the hashboards """
        # Must populate the full json POST data built from all the fields on the page
        data = self.build_mining_config(board_1, board_2, board_3)
        res = self.session.post(url=f"http://{self.ip_address}/cgi-bin/luci/admin/miner/cfg_save/", json=data)

        # Must send a GET request to `cfg_apply` to apply the changes
        self.session.get(f"http://{self.ip_address}/cgi-bin/luci/admin/miner/cfg_apply/")


    def stop_mining(self):
        """ Enable the hashboards """
        # Must populate the full json POST data built from all the fields on the page
        data = self.build_mining_config(False, False, False)
        res = self.session.post(url=f"http://{self.ip_address}/cgi-bin/luci/admin/miner/cfg_save/", json=data)

        # Must send a GET request to `cfg_apply` to apply the changes
        self.session.get(f"http://{self.ip_address}/cgi-bin/luci/admin/miner/cfg_apply/")


    # def get_power_limit(self) -> int:
    #     # res = self.session.get(f"http://{self.ip_address}/cgi-bin/luci/admin/miner/api_status")
    #     # if res.status_code == 200:
    #     #     return res.json()["tunerstatus"][0]["TUNERSTATUS"][0]["PowerLimit"]
    #     # elif res.status_code == 500:
    #     #     return None
    #     # else:
    #     #     raise Exception(f"ERROR: status_code: {res.status_code}")
    #     self.driver.get(f"http://{ip_address}/cgi-bin/luci/admin/miner/config")
    #     power_limit = self.driver.find_element(By.NAME, 'psu_power_limit')
    #     return int(power_limit.get_attribute("value"))


    # def set_power_limit(self, limit:int = 100):
    #     self.driver.get(f"http://{ip_address}/cgi-bin/luci/admin/miner/config")
    #     power_limit = self.driver.find_element(By.NAME, "psu_power_limit")
    #     power_limit.clear()
    #     power_limit.send_keys(limit)
    #     self.driver.find_element(By.CLASS_NAME, "cbi-button-apply").click()



import argparse
import boto3
import configparser
import datetime
import json
import time

from decimal import Decimal

import comed_api


parser = argparse.ArgumentParser(description='ASIC manager for S9 on Braiins OS')

# Required positional arguments
parser.add_argument('electricity_price_limit', type=Decimal,
                    help="Threshold above which the ASIC stops mining")

# Optional switches
parser.add_argument('-c', '--settings',
                    default="settings.conf",
                    dest="settings_config",
                    help="Override default settings config file location")

parser.add_argument('-r', '--resume_mining_after',
                    default=3,
                    type=int,
                    dest="resume_mining_after",
                    help="Number of consecutive price periods that must be below the price threshold before mining will resume")

parser.add_argument('-f', '--force_power_off',
                    action="store_true",
                    default=False,
                    dest="force_power_off",
                    help="Stops mining and exits")

parser.add_argument('-d1', '--deactivate_board_1',
                    action="store_true",
                    default=False,
                    dest="deactivate_1",
                    help="Run with hashboard 1 deactivated")

parser.add_argument('-d2', '--deactivate_board_2',
                    action="store_true",
                    default=False,
                    dest="deactivate_2",
                    help="Run with hashboard 2 deactivated")

parser.add_argument('-d3', '--deactivate_board_3',
                    action="store_true",
                    default=False,
                    dest="deactivate_3",
                    help="Run with hashboard 3 deactivated")


if __name__ == "__main__":
    args = parser.parse_args()

    electricity_price_limit = args.electricity_price_limit
    resume_mining_after = args.resume_mining_after
    force_power_off = args.force_power_off
    deactivate_1 = args.deactivate_1
    deactivate_2 = args.deactivate_2
    deactivate_3 = args.deactivate_3

    # Read settings
    arg_config = configparser.ConfigParser()
    arg_config.read(args.settings_config)

    admin_password = arg_config.get('ASIC', 'ADMIN_PASSWORD')
    admin_username = arg_config.get('ASIC', 'ADMIN_USERNAME')
    ip_address = arg_config.get('ASIC', 'IP_ADDRESS')
    power_limit_high = int(arg_config.get('ASIC', 'POWER_LIMIT_HIGH'))
    power_limit_low = int(arg_config.get('ASIC', 'POWER_LIMIT_LOW'))

    # weather_api_key = arg_config.get('APIS', 'WEATHER_API_KEY')
    # weather_zip_code = arg_config.get('APIS', 'WEATHER_ZIP_CODE')

    sns_topic = arg_config.get('AWS', 'SNS_TOPIC')
    aws_access_key_id = arg_config.get('AWS', 'AWS_ACCESS_KEY_ID')
    aws_secret_access_key = arg_config.get('AWS', 'AWS_SECRET_ACCESS_KEY')

    # Prep boto SNS client for email notifications
    sns = boto3.client(
        "sns",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name="us-east-1"     # N. Virginia
    )

    try:
        braiins_s9 = BraiinsS9(ip_address=ip_address, username=admin_username, password=admin_password)

        if force_power_off:
            # Shut down the miner and exit
            braiins_s9.stop_mining()
            subject = f"STOPPING miner via force_power_off"
            msg = "Stopped mining"
            # sns.publish(
            #     TopicArn=sns_topic,
            #     Subject=subject,
            #     Message=msg
            # )
            print(f"{datetime.datetime.now()}: {subject}")
            print(msg)
            exit()

        # Get the current electricity price
        try:
            prices = comed_api.get_last_hour()
        except Exception as e:
            print(f"First attempt to reach ComEd API: {repr(e)}")
            # Wait and try again before giving up
            time.sleep(30)
            try:
                prices = comed_api.get_last_hour()
            except Exception as e:
                print(f"Second attempt to reach ComEd API: {repr(e)}")

                # if the real-time price API is down, assume the worst and shut down
                braiins_s9.stop_mining()
                subject = f"STOPPING miner @ UNKNOWN ¢/kWh"
                msg = "ComEd real-time price API is down"
                # sns.publish(
                #     TopicArn=sns_topic,
                #     Subject=subject,
                #     Message=msg
                # )
                print(f"{datetime.datetime.now()}: {subject}")
                print(msg)
                exit()

        (cur_timestamp, cur_electricity_price) = prices[0]

        # Get current ASIC status
        is_mining = braiins_s9.is_mining

        if is_mining:
            # Also retrieve temps, hashrate, etc
            pass
            # try:
            #     result = WhatsminerAPI.get_read_only_info(whatsminer_token, cmd='summary')
            #     power = result['SUMMARY'][0]['Power']
            #     env_temp = result['SUMMARY'][0]['Env Temp']
            #     freq_avg = result['SUMMARY'][0]['freq_avg']
            #     fan_speed_in = result['SUMMARY'][0]['Fan Speed In']
            #     fan_speed_out = result['SUMMARY'][0]['Fan Speed Out']
            #     hashrate_1m = result['SUMMARY'][0]['MHS 1m']
            #     status = {
            #         "power": power,
            #         "env_temp": env_temp,
            #         "freq_avg": freq_avg,
            #         "fan_speed_in": fan_speed_in,
            #         "fan_speed_out": fan_speed_out,
            #         "hashrate_1m": "%4.1f TH/s" % (hashrate_1m / 1000000),
            #     }

            #     result = WhatsminerAPI.get_read_only_info(whatsminer_token, cmd='edevs')
            #     hashboards = []
            #     for board in result['DEVS']:
            #         hashboards.append({
            #             "temp": board['Temperature'],
            #             "hashrate_1m": "%.1f TH/s" % (board['MHS 1m'] / 1000000),
            #         })
            #     status["hashboards"] = hashboards

            #     print(f"""{datetime.datetime.now():%Y-%m-%d %H:%M:%S}: is_mining: {is_mining}  |  {cur_electricity_price:5.1f} ¢/kWh  |  {status["power"]:4d}W  |  {status["env_temp"] * 1.8 + 32:5.1f}F ({status["env_temp"]}C)  |  {status["fan_speed_in"]}-{status["fan_speed_out"]}rpm  |  {status["hashrate_1m"]}  |  {", ".join([str(hb["temp"]) for hb in status["hashboards"]])}""")
            # except Exception as e:
            #     # Log it but don't worry; can get bad response if mining just recently resumed.
            #     print(repr(e))
            #     fan_speed_in = 0
            #     freq_avg = 0


        print(f"{datetime.datetime.now()}: is_mining: {is_mining} | cur_electricity_price: {cur_electricity_price:0.2f}¢/kWh | limit: {electricity_price_limit:0.2f}¢/kWh")


        if is_mining and cur_electricity_price > electricity_price_limit:
            # Stop mining, we've passed the price threshold
            braiins_s9.stop_mining()
            subject = f"STOPPING miner @ {cur_electricity_price:0.2f}¢/kWh"
            # sns.publish(
            #     TopicArn=sns_topic,
            #     Subject=subject,
            #     Message=msg
            # )
            print(f"{datetime.datetime.now()}: {subject}")
            # print(msg)

        elif not is_mining and cur_electricity_price < electricity_price_limit:
            # Resume mining? Electricity price has fallen below our threshold; but don't
            #   get faked out by a single period dropping. Must see n periods in a row 
            #   (`resume_mining_after`) below the price threshold before resuming.
            resume_mining = True
            for i in range(1, resume_mining_after + 1):
                (ts, price) = prices[i]
                if price >= electricity_price_limit:
                    resume_mining = False
                    break

            if resume_mining:
                braiins_s9.start_mining(board_1=deactivate_1 == False, board_2=deactivate_2 == False, board_3=deactivate_3 == False)
                subject = f"RESTARTING miner @ {cur_electricity_price:0.2f}¢/kWh"
                # msg = json.dumps(response, indent=4)
                # sns.publish(
                #     TopicArn=sns_topic,
                #     Subject=subject,
                #     Message=msg
                # )
                print(f"{datetime.datetime.now()}: {subject}")
                # print(msg)

    finally:
        braiins_s9.quit()
