import requests
import json
import time
import os
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

HOST = 'https://127.0.0.1:2999'

# r = requests.get(f'{HOST}/replay/render', verify=False)
# print(r.text)

def get_gameInfo():
    r = requests.get(f'{HOST}/replay/playback', verify=False)
    data = r.text
    print(data)
    return json.loads(data)

def start_recording(end_time):
    data = {
      "codec": "webm",
      "endTime": end_time,
      "enforceFrameRate": False,
      "framesPerSecond": 120,
      "lossless": True,
      "recording": True,
      "replaySpeed": 8,
      "startTime": 0,
      "path": "C:\\Users\\songm\\Desktop\\Replays"
    }
    r = requests.post(f'{HOST}/replay/recording', json=data, verify=False)
    data = r.text
    print(data)
    return json.loads(data)

def get_record_status():
    r = requests.get(f'{HOST}/replay/recording', verify=False)
    data = r.text
    print('get_record_status :', data)
    return json.loads(data)

d = get_gameInfo()
gameTime = d['length']
print('[*] gameTime:', gameTime)

d = start_recording(gameTime)
recording = True
while recording:
    d = get_record_status()
    recording = d['recording']
    percent = d['currentTime'] / d['endTime'] * 100
    print(f'percent : {percent:.2f}%')
    time.sleep(1)

print("Complete")
os.system('taskkill /f /im "League of Legends.exe"')