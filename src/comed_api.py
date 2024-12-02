import datetime
import requests

from datetime import timezone
from decimal import Decimal


def get_prices(tz=timezone.utc, limit: int = None):
    r = requests.get("https://hourlypricing.comed.com/api?type=5minutefeed")
    prices = []
    for index, entry in enumerate(r.json()):
        if limit and index >= limit:
            break
        cur_seconds = float(Decimal(entry['millisUTC'])/Decimal('1000.0'))

        if tz == timezone.utc:
            cur_timestamp = datetime.datetime.fromtimestamp(cur_seconds, tz=timezone.utc)
        else:
            cur_timestamp = tz.localize(datetime.datetime.fromtimestamp(cur_seconds))

        cur_price = Decimal(entry['price'])

        prices.append((cur_timestamp, cur_price))

    return prices


def get_cur_electricity_price():
    r = requests.get("https://hourlypricing.comed.com/api?type=5minutefeed")
    entry = r.json()[0]
    cur_seconds = float(Decimal(entry['millisUTC'])/Decimal('1000.0'))

    # If we need it in local time
    # tz = pytz.timezone("America/Chicago")
    # cur_timestamp = tz.localize(datetime.datetime.fromtimestamp(cur_seconds))

    # If we want it in UTC
    cur_timestamp = datetime.datetime.fromtimestamp(cur_seconds, tz=timezone.utc)

    cur_price = Decimal(entry['price'])

    return (cur_timestamp, cur_price)


def get_last_hour():
    r = requests.get("https://hourlypricing.comed.com/api?type=5minutefeed")
    prices = []
    for i in range(0, 12):
        entry = r.json()[i]
        cur_seconds = float(Decimal(entry['millisUTC'])/Decimal('1000.0'))

        # If we need it in local time
        # tz = pytz.timezone("America/Chicago")
        # cur_timestamp = tz.localize(datetime.datetime.fromtimestamp(cur_seconds))

        # If we want it in UTC
        cur_timestamp = datetime.datetime.fromtimestamp(cur_seconds, tz=timezone.utc)

        cur_price = Decimal(entry['price'])

        prices.append((cur_timestamp, cur_price))

    return prices
