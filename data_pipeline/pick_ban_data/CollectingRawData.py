
from riotwatcher import LolWatcher


#Initial Setting for API (change this later)
config = {"api_id": "RGAPI-167cb091-6230-48e0-9c5e-3ad733d3fa4d",
          "api_id_1": "RGAPI-7766b4e6-fe20-48b6-849c-33b203bc20df",
          "api_id_2": "RGAPI-cb56e6de-45a1-435a-9c5f-438b7b17dbb1",
          "api_id_3": "RGAPI-004bacfa-71ea-42fa-a584-82f116a89b99",
          "api_id_4": "RGAPI-31ab9e5a-3c98-468f-b20c-4b5f239c248b",
          "api_id_5": "RGAPI-361db347-6ef6-473b-b003-ab49b1f8bc40",
          "api_id_6": "RGAPI-4558855f-52fc-47c4-a83e-a9993995dfd5",
          "api_id_7": "RGAPI-a6fdeab3-cf7f-415e-aa2f-681e4cdd4a2d",
          "api_id_8":"RGAPI-16b8a477-e6e0-4754-ac43-6051a631b7e7",
          "api_id_9":"RGAPI-8408917a-eb2d-4a97-845d-0b3fd77e3fba",
          "api_id_10": "RGAPI-c0431b49-c02b-41c5-a464-182bb233db64",
          "api_id_11": "RGAPI-ab23377f-700b-4c23-8a76-f9c89837c0db",
          "api_id_12": "RGAPI-da494f63-b923-4d02-afdb-6996d7667eb8"
          }

#Setting initial values (config)

region = "ASIA"
with open("summoner_name1.csv") as f:
    names = f.readlines()

num = 0
for i in names:
    i = i[:-1]
    num += 1
    x = num % 11
    api = LolWatcher(config[list(config.keys())[x]])
    summoner_name = i
    try:
        summoner_id = api.summoner.by_name("kr", summoner_name)["puuid"]
    except:
        continue
    matchlist = api.match_v5.matchlist_by_puuid("ASIA", summoner_id, queue=420)

    for gameId in matchlist:
        matchinfo = api.match_v5.by_id("ASIA", gameId)

        if matchinfo["info"]["queueId"] != 420:
            #print(matchinfo["info"]["queueId"])
            #print(num)
            continue


        participants = matchinfo["info"]["participants"]
        #print(participants[0]["teamId"])
        #print(participants[0]["win"])

        if (participants[0]["teamId"] == 100 and participants[0]["win"] == True) or (participants[0]["teamId"] != 100 and participants[0]["win"] != "Win"):
            Win = 1
        else:
            Win = 0

        Blue = []
        Red = []
        Ban = [0,0,0,0,0,0,0,0,0,0]
        K = matchinfo["info"]["teams"][0]["bans"]
        #print(K)
        for i in K:
            Ban[i["pickTurn"]-1] = i["championId"]

        K = matchinfo["info"]["teams"][1]["bans"]
        for i in K:
            Ban[i["pickTurn"] - 1] = i["championId"]


        for i in range(10):
            if participants[i]["teamId"] == 100:
                Blue.append(participants[i]["championId"])
            elif participants[i]["teamId"] == 200:
                Red.append(participants[i]["championId"])
            else:
                print("Error team Id does not exist: " + "teamId =" + participants[i]["teamId"])

        if Blue[0] == Blue[1]:
            continue
        """
        with open("match_data_ban.csv", "a") as f:
            line = str([gameId]) + ","  + str(Ban) + "," + str(Blue) + "," + str(Red) + "," + str([Win]) + "\n"
            f.write(line)
    
        with open("game_ban.csv", "a") as f:
            line = str(gameId) + ", "
            f.write(line)
        """
        #print(gameId)
        #print("check")


















