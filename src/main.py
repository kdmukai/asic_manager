import argparse
import asyncio
# import boto3
import configparser
import datetime
import json
import time

from decimal import Decimal
from pyasic import get_miner
from pyasic.miners.base import BaseMiner

import comed_api as comed_api



async def run(arg_config: configparser.ConfigParser):
    ip_address = arg_config.get('ASIC', 'IP_ADDRESS')
    max_freq = arg_config.getint('ASIC', 'MAX_FREQ')
    min_freq = arg_config.getint('ASIC', 'MIN_FREQ')
    freq_step = arg_config.getint('ASIC', 'FREQ_STEP')
    max_electricity_price = Decimal(arg_config.get('ASIC', 'MAX_ELECTRICITY_PRICE'))
    resume_after = arg_config.getint('ASIC', 'RESUME_AFTER')

    # weather_api_key = arg_config.get('APIS', 'WEATHER_API_KEY')
    # weather_zip_code = arg_config.get('APIS', 'WEATHER_ZIP_CODE')

    # sns_topic = arg_config.get('AWS', 'SNS_TOPIC')
    # aws_access_key_id = arg_config.get('AWS', 'AWS_ACCESS_KEY_ID')
    # aws_secret_access_key = arg_config.get('AWS', 'AWS_SECRET_ACCESS_KEY')

    # # Prep boto SNS client for email notifications
    # sns = boto3.client(
    #     "sns",
    #     aws_access_key_id=aws_access_key_id,
    #     aws_secret_access_key=aws_secret_access_key,
    #     region_name="us-east-1"     # N. Virginia
    # )

    # if force_power_off:
    #     # Shut down the miner and exit
    #     whatsminer_token.enable_write_access(admin_password=admin_password)
    #     response = WhatsminerAPI.exec_command(whatsminer_token, cmd='power_off', additional_params={"respbefore": "false"})
    #     subject = f"STOPPING miner via force_power_off"
    #     msg = "force_power_off called"
    #     sns.publish(
    #         TopicArn=sns_topic,
    #         Subject=subject,
    #         Message=msg
    #     )
    #     print(f"{datetime.datetime.now()}: {subject}")
    #     print(msg)
    #     print(json.dumps(response, indent=4))
    #     exit()

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
            # whatsminer_token.enable_write_access(admin_password=admin_password)
            # response = WhatsminerAPI.exec_command(whatsminer_token, cmd='power_off', additional_params={"respbefore": "false"})
            # subject = f"STOPPING miner @ UNKNOWN ¢/kWh"
            # msg = "ComEd real-time price API is down"
            # sns.publish(
            #     TopicArn=sns_topic,
            #     Subject=subject,
            #     Message=msg
            # )
            # print(f"{datetime.datetime.now()}: {subject}")
            # print(msg)
            # print(json.dumps(response, indent=4))
            exit()

    (cur_timestamp, cur_electricity_price) = prices[0]

    # Get the miner
    miner: BaseMiner = await get_miner(ip_address)
    config = await miner.get_config()
    cur_freq = int(config.mining_mode.global_freq)


    # if is_mining:
    #     # Also retrieve temps, hashrate, etc
    #     try:
    #         result = WhatsminerAPI.get_read_only_info(whatsminer_token, cmd='summary')
    #         power = result['SUMMARY'][0]['Power']
    #         env_temp = result['SUMMARY'][0]['Env Temp']
    #         freq_avg = result['SUMMARY'][0]['freq_avg']
    #         fan_speed_in = result['SUMMARY'][0]['Fan Speed In']
    #         fan_speed_out = result['SUMMARY'][0]['Fan Speed Out']
    #         hashrate_1m = result['SUMMARY'][0]['MHS 1m']
    #         status = {
    #             "power": power,
    #             "env_temp": env_temp,
    #             "freq_avg": freq_avg,
    #             "fan_speed_in": fan_speed_in,
    #             "fan_speed_out": fan_speed_out,
    #             "hashrate_1m": "%4.1f TH/s" % (hashrate_1m / 1000000),
    #         }

    #         result = WhatsminerAPI.get_read_only_info(whatsminer_token, cmd='edevs')
    #         hashboards = []
    #         for board in result['DEVS']:
    #             hashboards.append({
    #                 "temp": board['Temperature'],
    #                 "hashrate_1m": "%.1f TH/s" % (board['MHS 1m'] / 1000000),
    #             })
    #         status["hashboards"] = hashboards

    #         print(f"""{datetime.datetime.now():%Y-%m-%d %H:%M:%S}: is_mining: {is_mining}  |  {cur_electricity_price:5.1f} ¢/kWh  |  {status["power"]:4d}W  |  {status["env_temp"] * 1.8 + 32:5.1f}F ({status["env_temp"]}C)  |  {status["fan_speed_in"]}-{status["fan_speed_out"]}rpm  |  {status["hashrate_1m"]}  |  {", ".join([str(hb["temp"]) for hb in status["hashboards"]])}""")
    #     except Exception as e:
    #         # Log it but don't worry; can get bad response if mining just recently resumed.
    #         print(repr(e))
    #         fan_speed_in = 0
    #         freq_avg = 0

    # else:
    #     print(f"""{datetime.datetime.now():%Y-%m-%d %H:%M:%S}: is_mining: {is_mining}  |  {cur_electricity_price:0.2f}¢/kWh""")

    subject = "Error?"

    if cur_electricity_price > max_electricity_price:
        # Reduce miner freq, we've passed the price threshold
        new_freq = cur_freq - freq_step
        if new_freq < min_freq:
            subject = "Already at min freq"
 
        else:        
            config.mining_mode.global_freq = new_freq
            result = await miner.send_config(config)

            subject = f"REDUCING miner freq @ {cur_electricity_price:0.2f}¢/kWh to {new_freq}"
            # msg = json.dumps(response, indent=4)
            # sns.publish(
            #     TopicArn=sns_topic,
            #     Subject=subject,
            #     Message=msg
            # )
            print(f"{datetime.datetime.now()}: {subject}")
            # print(msg)

    elif cur_electricity_price < max_electricity_price:
        # Resume mining? Electricity price has fallen below our threshold; but don't
        #   get faked out by a single period dropping. Must see n periods in a row 
        #   (`resume_mining_after`) below the price threshold before resuming.
        resume_mining = True
        for i in range(1, resume_after + 1):
            (ts, price) = prices[i]
            if price >= max_electricity_price:
                resume_mining = False
                break

        if resume_mining:
            new_freq = cur_freq + freq_step
            if new_freq > max_freq:
                subject = "Already at max freq"

            else:
                config.mining_mode.global_freq = new_freq
                result = await miner.send_config(config)

                subject = f"INCREASING miner freq @ {cur_electricity_price:0.2f}¢/kWh to {new_freq}"
                # msg = json.dumps(response, indent=4)
                # sns.publish(
                #     TopicArn=sns_topic,
                #     Subject=subject,
                #     Message=msg
                # )
                print(f"{datetime.datetime.now()}: {subject}")
                # print(msg)

    print(f"{datetime.datetime.now()}: freq: {cur_freq} MHz ({min_freq}-{max_freq}) | {cur_electricity_price:0.2f}¢/kWh | {subject}")




parser = argparse.ArgumentParser(description='vnish custom manager')

# Required positional arguments
# parser.add_argument('max_electricity_price', type=Decimal,
#                     help="Threshold above which the ASIC reduces chip frequency")

# Optional switches
parser.add_argument('-c', '--settings',
                    default="settings.conf",
                    dest="settings_config",
                    help="Override default settings config file location")

# parser.add_argument('-f', '--force_power_off',
#                     action="store_true",
#                     default=False,
#                     dest="force_power_off",
#                     help="Stops mining and exits")



args = parser.parse_args()

# force_power_off = args.force_power_off

# Read settings
arg_config = configparser.ConfigParser()
arg_config.read(args.settings_config)

asyncio.run(run(arg_config))
