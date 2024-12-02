import requests


def get_current_weather(api_key:str, zip_code:str):
    """
        {
            "location": {
                "name": "Your Town",
                "region": "Somestate",
                "country": "USA",
                "lat": xx.xx,
                "lon": -xx.xx,
                "tz_id": "America/xxxxxxxxxx",
                "localtime_epoch": 1629831164,
                "localtime": "2021-08-24 13:52"
            },
            "current": {
                "last_updated_epoch": 1629830700,
                "last_updated": "2021-08-24 13:45",
                "temp_c": 33.3,
                "temp_f": 91.9,
                "is_day": 1,
                "condition": {
                    "text": "Partly cloudy",
                    "icon": "//cdn.weatherapi.com/weather/64x64/day/116.png",
                    "code": 1003
                },
                "wind_mph": 11.9,
                "wind_kph": 19.1,
                "wind_degree": 210,
                "wind_dir": "SSW",
                "pressure_mb": 1014.0,
                "pressure_in": 29.94,
                "precip_mm": 3.5,
                "precip_in": 0.14,
                "humidity": 56,
                "cloud": 25,
                "feelslike_c": 47.2,
                "feelslike_f": 116.9,
                "vis_km": 16.0,
                "vis_miles": 9.0,
                "uv": 6.0,
                "gust_mph": 14.8,
                "gust_kph": 23.8
            }
        }
    """
    url = f"https://api.weatherapi.com/v1/current.json?key={api_key}&q={zip_code}&aqi=no"
    r = requests.get(url)

    return r.json()["current"]
