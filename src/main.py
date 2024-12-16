import argparse
import asyncio
# import boto3
import configparser
import datetime
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
    max_temp = arg_config.getint('ASIC', 'MAX_TEMP')
    resume_at_temp = arg_config.getint('ASIC', 'RESUME_AT_TEMP')
    temp_freq_step = arg_config.getint('ASIC', 'TEMP_FREQ_STEP')

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
            # subject = f"STOPPING miner @ UNKNOWN ¢/kWh"
            # msg = "ComEd real-time price API is down"
            # sns.publish(
            #     TopicArn=sns_topic,
            #     Subject=subject,
            #     Message=msg
            # )
            # print(f"{datetime.datetime.now()}: {subject}")
            exit()

    (cur_timestamp, cur_electricity_price) = prices[0]

    # Get the miner
    miner: BaseMiner = await get_miner(ip_address)
    if not miner:
        print(f"{datetime.datetime.now()}: Miner not found at {ip_address}")
        exit()
    
    hashboards = await miner.get_hashboards()
    cur_temp = max(board.temp for board in hashboards if board.temp)

    config = await miner.get_config()
    cur_freq = int(config.mining_mode.global_freq)
    new_freq_due_to_price = cur_freq

    subject = "Error?"

    is_holding_due_to_price = False
    if cur_electricity_price > max_electricity_price:
        # Reduce miner freq, we've passed the price threshold
        new_freq_due_to_price = max(min_freq, cur_freq - freq_step)
        if new_freq_due_to_price == cur_freq:
            subject = "Already at min freq"
 
        else:
            config.mining_mode.global_freq = new_freq_due_to_price

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
            new_freq_due_to_price = min(max_freq, cur_freq + freq_step)
            if new_freq_due_to_price == cur_freq:
                subject = "Already at max freq"

            else:
                config.mining_mode.global_freq = new_freq_due_to_price
        
        else:
            is_holding_due_to_price = True
            subject = f"Holding freq, pending {resume_after} periods below threshold"

    new_freq_due_to_temp = cur_freq
    if cur_temp >= max_temp:
        # Reduce miner freq, we've passed the temperature threshold
        new_freq_due_to_temp = cur_freq - temp_freq_step  # we do NOT respect min_freq because heat death is bad
        is_holding_due_to_price = False

    elif cur_temp < resume_at_temp and cur_freq < max_freq and not is_holding_due_to_price:
        # Resume mining? Temperature has fallen below our threshold
        new_freq_due_to_temp = min(max_freq, cur_freq + temp_freq_step)
    
    else:
        # We are within our temp bounds; don't allow low price to increase temp
        if new_freq_due_to_price > cur_freq:
            new_freq_due_to_price = cur_freq
            if not is_holding_due_to_price:
                # Avoid overwriting the subject if we're already holding due to price
                subject = f"Holding in target temp range"

    if new_freq_due_to_price != cur_freq or new_freq_due_to_temp != cur_freq:
        # Have to decide which change to apply; heat takes precedence.
        if new_freq_due_to_temp < cur_freq:
            # Must ramp down due to temp
            new_freq = new_freq_due_to_temp
            subject = f"REDUCING miner freq to {new_freq} MHz due to temp"

        elif new_freq_due_to_price < cur_freq:
            # Electricity costs are forcing us to ramp down
            new_freq = new_freq_due_to_price
            subject = f"REDUCING miner freq to {new_freq} MHz due to price"

        elif new_freq_due_to_temp > cur_freq and new_freq_due_to_price > cur_freq:
            # Can only increase if both temp and price allow for it; use the slower step increase
            new_freq = new_freq_due_to_temp
            subject = f"INCREASING miner freq to {new_freq} MHz"

        else:
            print("UNHANDLED CASE!")

        config.mining_mode.global_freq = new_freq
        await miner.send_config(config)

    print(f"{datetime.datetime.now()}: freq: {cur_freq} MHz ({min_freq}-{max_freq}) | {cur_electricity_price:0.2f}¢/kWh ({max_electricity_price}) | {cur_temp}°C ({resume_at_temp}-{max_temp}) | {subject}")




parser = argparse.ArgumentParser(description='vnish custom manager')

# Optional switches
parser.add_argument('-c', '--settings',
                    default="settings.conf",
                    dest="settings_config",
                    help="Override default settings config file location")

args = parser.parse_args()

# Read settings
arg_config = configparser.ConfigParser()
arg_config.read(args.settings_config)

asyncio.run(run(arg_config))
