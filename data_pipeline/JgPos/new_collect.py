import requests
import json
import time
import os,glob
import ffmpeg
from lcu_driver import Connector
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
#import replayspeed
import gameId
HOST = 'https://127.0.0.1:2999'

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
      "path": "C:\\Users\\Administrator\\Desktop\\Replays"
    }
    #r = requests.post(f'{HOST}/replay/recording', json=data, verify=False)
    r = requests.post(f'{HOST}/replay/recording', json={"endTime": end_time, "replaySpeed": 8}, verify=False)
    data = r.text
    print(data)
    return json.loads(data)

def get_record_status():
    r = requests.get(f'{HOST}/replay/recording', verify=False)
    data = r.text
    print('get_record_status :', data)
    return json.loads(data)

connector = Connector()

@connector.ready
async def connect(connection):
    game_id_list = gameId.get_data()

    for i in game_id_list:
        while True:
            try:
                download = await connection.request('post', f'/lol-replays/v1/rofls/{i}/download', data={'gameId': i})
                print(download)
                time.sleep(8)
                play = await connection.request('post', f'/lol-replays/v1/rofls/{i}/watch', data={'gameId' : i})
                print(play)

                time.sleep(25)

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

                print(f"{i} : Recording Complete")
                os.system('taskkill /f /im "League of Legends.exe"')
                original_file = f'C:\\Users\\Administrator\\Documents\\League of Legends\\Highlights\\11-23_KR-{i}_01.webm'
                stream = ffmpeg.input(original_file)
                stream = ffmpeg.crop(stream, 1391, 692, 289, 289)
                stream = ffmpeg.output(stream, f'C:\\Users\\Administrator\\Desktop\\Replays\\{i}.webm')
                ffmpeg.run(stream)
                os.remove(original_file)
                print(f"{i} : Process Complete")
            except:
                os.system('taskkill /f /im "League of Legends.exe"')
                print(f"{i} : Error, retrying..")
                directory = f'C:\\Users\\Administrator\\Documents\\League of Legends\\Highlights\\11-23_KR-{i}_*'
                for filename in glob.glob(directory):
                    os.remove(filename)
                continue
            break

@connector.close
async def disconnect(connection):
    print('Finished task')

connector.start()

