import argparse
import boto3
import configparser
import datetime
import json
import requests

from decimal import Decimal

import comed_api
from whatsminer import WhatsminerAccessToken, WhatsminerAPI



parser = argparse.ArgumentParser(description='Whatsminer custom manager')

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


if __name__ == "__main__":
    args = parser.parse_args()

    electricity_price_limit = args.electricity_price_limit
    resume_mining_after = args.resume_mining_after
    force_power_off = args.force_power_off

    # Read settings
    arg_config = configparser.ConfigParser()
    arg_config.read(args.settings_config)

    admin_password = arg_config.get('ASIC', 'ADMIN_PASSWORD')
    ip_address = arg_config.get('ASIC', 'IP_ADDRESS')

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

    whatsminer_token = WhatsminerAccessToken(ip_address=ip_address)

    if force_power_off:
        # Shut down the miner and exit
        whatsminer_token.enable_write_access(admin_password=admin_password)
        response = WhatsminerAPI.exec_command(whatsminer_token, cmd='power_off', additional_params={"respbefore": "false"})
        subject = f"STOPPING miner via force_power_off"
        msg = "force_power_off called"
        sns.publish(
            TopicArn=sns_topic,
            Subject=subject,
            Message=msg
        )
        print(f"{datetime.datetime.now()}: {subject}")
        print(msg)
        print(json.dumps(response, indent=4))
        exit()

    # Get the current electricity price
    try:
        prices = comed_api.get_last_hour()
    except requests.exceptions.ConnectionError as e:
        # if the real-time price API is down, assume the worst and shut down
        whatsminer_token.enable_write_access(admin_password=admin_password)
        response = WhatsminerAPI.exec_command(whatsminer_token, cmd='power_off', additional_params={"respbefore": "false"})
        subject = f"STOPPING miner @ UNKNOWN ¢/kWh"
        msg = "ComEd real-time price API is down"
        sns.publish(
            TopicArn=sns_topic,
            Subject=subject,
            Message=msg
        )
        print(f"{datetime.datetime.now()}: {subject}")
        print(msg)
        print(json.dumps(response, indent=4))
        exit()

    (cur_timestamp, cur_electricity_price) = prices[0]

    # Get current ASIC status
    result = WhatsminerAPI.get_read_only_info(whatsminer_token, cmd="status")
    is_mining = result['Msg']['btmineroff'] == 'false'

    if is_mining:
        # Also retrieve temps, hashrate, etc
        try:
            result = WhatsminerAPI.get_read_only_info(whatsminer_token, cmd='summary')
            power = result['SUMMARY'][0]['Power']
            env_temp = result['SUMMARY'][0]['Env Temp']
            freq_avg = result['SUMMARY'][0]['freq_avg']
            fan_speed_in = result['SUMMARY'][0]['Fan Speed In']
            fan_speed_out = result['SUMMARY'][0]['Fan Speed Out']
            hashrate_1m = result['SUMMARY'][0]['MHS 1m']
            status = {
                "power": power,
                "env_temp": env_temp,
                "freq_avg": freq_avg,
                "fan_speed_in": fan_speed_in,
                "fan_speed_out": fan_speed_out,
                "hashrate_1m": "%.1fTH/s" % (hashrate_1m / 1000000),
            }

            result = WhatsminerAPI.get_read_only_info(whatsminer_token, cmd='edevs')
            hashboards = []
            for board in result['DEVS']:
                hashboards.append({
                    "temp": board['Temperature'],
                    "hashrate_1m": "%.1fTH/s" % (board['MHS 1m'] / 1000000),
                })
            status["hashboards"] = hashboards

            print(json.dumps(status, indent=4))
        except Exception as e:
            # Log it but don't worry; can get bad response if mining just recently resumed.
            print(repr(e))
            fan_speed_in = 0
            freq_avg = 0

    if is_mining and cur_electricity_price > electricity_price_limit:
        # Stop mining, we've passed the price threshold
        whatsminer_token.enable_write_access(admin_password=admin_password)
        response = WhatsminerAPI.exec_command(whatsminer_token, cmd='power_off', additional_params={"respbefore": "false"})
        subject = f"STOPPING miner @ {cur_electricity_price:0.2f}¢/kWh"
        msg = json.dumps(response, indent=4)
        sns.publish(
            TopicArn=sns_topic,
            Subject=subject,
            Message=msg
        )
        print(f"{datetime.datetime.now()}: {subject}")
        print(msg)

    elif not is_mining and cur_electricity_price < electricity_price_limit:
        # Resume mining? Electricity price has fallen below our threshold; but don't
        #   get faked out by a single period dropping. Must see num_restart_periods in a row below
        #   threshold before resuming.
        resume_mining = True
        for i in range(1, resume_mining_after + 1):
            (ts, price) = prices[i]
            if price >= electricity_price_limit:
                resume_mining = False
                break

        if resume_mining:
            whatsminer_token.enable_write_access(admin_password=admin_password)
            response = WhatsminerAPI.exec_command(whatsminer_token, cmd='power_on')
            subject = f"RESTARTING miner @ {cur_electricity_price:0.2f}¢/kWh"
            msg = json.dumps(response, indent=4)
            sns.publish(
                TopicArn=sns_topic,
                Subject=subject,
                Message=msg
            )
            print(f"{datetime.datetime.now()}: {subject}")
            print(msg)

    print(f"{datetime.datetime.now()}: is_mining: {is_mining} | cur_electricity_price: {cur_electricity_price:0.2f}¢/kWh")


    # percent = None
    # if is_mining and fan_speed_in >= 7600 and freq_avg >= 920:
    #     # We're running full-out and too hot; slow down
    #     percent = "-1"

    # elif is_mining and fan_speed_in >= 7600 and freq_avg >= 850:
    #     # Have to ramp down further
    #     percent = "-2"

    # if percent is not None:
    #     whatsminer_token.enable_write_access(admin_password=admin_password)
    #     response = WhatsminerAPI.exec_command(whatsminer_token, cmd='set_target_freq', additional_params={"percent": percent})
    #     subject = f"REDUCING miner frequency @ {freq_avg} / {fan_speed_in}rpm to \"{percent}\""
    #     msg = f"{cur_timestamp}: " + json.dumps(response, indent=4)
    #     sns.publish(
    #         TopicArn=sns_topic,
    #         Subject=subject,
    #         Message=msg
    #     )
    #     print(f"{datetime.datetime.now()}: {subject}")
    #     print(msg)

