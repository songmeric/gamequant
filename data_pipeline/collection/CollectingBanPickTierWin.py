
from riotwatcher import LolWatcher

game = []
"""
#reading gameId list
with open("game_ban1.csv", "r") as f:
    game = f.read().split(", ")
f.close()
"""
#Initial Setting for API (change this later)
config = {"api_id": "RGAPI-b3e3a369-9314-43ab-ac62-17c93630268a",
          "api_id_1": "RGAPI-7f88bc6b-a4dc-47af-bcbb-166d08bc7494",
          "api_id_2": "RGAPI-91df06f3-cf41-4621-9fb5-27807266e81e",
          "api_id_3": "RGAPI-7059cc11-7c53-4de3-8c1d-5eb93765a676",
          "api_id_4": "RGAPI-45e01cc3-7e28-47ad-bdad-d788f8fd2aa0",
          "api_id_5": "RGAPI-a4b93b9d-ace8-4482-98ec-bb9b91ca438a",
          "api_id_6": "RGAPI-22680015-e980-4cb9-8251-d2f9a24cf019",
          "api_id_7": "RGAPI-bb1b81e4-50db-4613-990e-a6a8cf67594a",
          "api_id_8":"RGAPI-ff9bc96b-222d-4163-985b-92f29ffb4f11",
          "api_id_9":"RGAPI-6051c772-2ea4-4474-9406-e396de768778",
          "api_id_10": "RGAPI-9725d718-0601-4ef8-b4ce-a4aa0b98ddad",
          "api_id_11": "RGAPI-bcf4a9b9-60fa-4904-85f1-c3bd6aa41317",
          "api_id_12": "RGAPI-8bad7b24-16f5-4aa1-b957-63bdc5f9a018"}

#Setting initial values (config)

region = "ASIA"
#for i in list(config.keys()):
    #api = LolWatcher(config[i])
    #summoner_name = api.league.challenger_by_queue("kr", queue="RANKED_SOLO_5x5")["entries"][0]["summonerName"]
    #summoner_id = api.summoner.by_name("kr", summoner_name)["puuid"]
    #print(summoner_id)
    #gameId = api.match_v5.matchlist_by_puuid("ASIA", summoner_id, queue=420)[0]
    #matchinfo = api.match_v5.by_id("ASIA", gameId)
    #print(matchinfo)
#if team 100 wins --> Win = 1
#while summoner_list:
#num = 5290023604
num = 5492327944
while True:
    #num += 1
    i = num
    x = num % 13
    api = LolWatcher(config[list(config.keys())[x]])

    try:
        print("here")
        gameId = "KR_" + str(num)
        matchinfo = api.match_v5.by_id("ASIA", gameId)
        if matchinfo["info"]["queueId"] != 420:
            print(matchinfo["info"]["queueId"])
            print(num)
            continue
        #print(matchinfo)
        if str(gameId) not in game:
            game.append(gameId)
        else:
            continue
        print(num)

    except:
        print(num)
        print("None")
        continue

    try:
        participants = matchinfo["info"]["participants"]
        #print(participants[0]["teamId"])
        #print(participants[0]["win"])
        participants_rank = []
        for i in range(10):
            try:
                summonerName = participants[i]['summonerName']
                print(summonerName)
                add1 = api.summoner.by_name("kr",summonerName)["id"]
                add = api.league.by_summoner("kr", add1)[0]["tier"]
            except:
                add = []
            participants_rank.append(add)


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

        Tier = ["C","G", "M", "D", "P", "GO", "S", "B"]
        Total_tier = 0
        Num_tier = 0
        for i in participants_rank:
            if i == []:
                continue
            Total_tier += 1
            for j in range(len(Tier)):
                if i[0] == Tier[j]:
                    if i[0] == "G":
                        if i[1] == "O":
                            Num_tier += 5
                        else:
                            Num_tier += 1
                    else:
                        Num_tier += j
        Tier = Tier[int(Num_tier/Total_tier)]
        print(Tier)

        if Blue[0] == Blue[1]:
            continue
        #print(Ban)
        #print(Blue)
        #print(Red)
        #print(Win)
        #print(participants_rank)

        with open("match_data_ban1.csv", "a") as f:
            line = str([gameId]) + ","  + str(Ban) + "," + str(Blue) + "," + str(Red) + "," + str(participants_rank) + "," + str([Tier]) + ","+ str([Win]) + "\n"
            f.write(line)

        with open("game_ban1.csv", "a") as f:
            line = str(gameId) + ", "
            f.write(line)

        print("check")

    except:
        print("fail")
        continue

