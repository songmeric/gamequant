from riotwatcher import LolWatcher, RiotWatcher
"""
Return data structure:
Stored in "match_data_ban.csv"
[gameID], [Ban], [BluePick], [RedPick], [ParticipantTier], [ParticipantPuuid], [AverageTier], [Win(Blue)]
Put '[' and ']' at both ends and pass it throuhg ast.literal_eval(<data>) to get read the result as a list
"""


"""
Make sure the "gameId_reply.csv" file is in the same folder. or change the code below.
"""
with open("gameId_reply.csv", "r") as f:
    Game = f.read().split(",")
Game = Game[:-1]

#Initial Setting for API (change this later)
"""
Make sure all the api keys below are activated
"""
config = {"api_id": "RGAPI-8d5e0759-7754-4f27-8178-531c4ec07883",
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

region = "ASIA"

for i in range(len(Game)):
    x = i % len(list(config.keys()))
    api = LolWatcher(config[list(config.keys())[x]])

    gameId = Game[i]
    matchinfo = api.match_v5.by_id("ASIA", gameId)

    participants = matchinfo["info"]["participants"]

    participants_puuid = matchinfo["metadata"]["participants"]
    participants_rank = []
    for i in range(10):
        try:
            summonerName = participants[i]['summonerName']
            add1 = api.summoner.by_name("kr", summonerName)["id"]
            add = api.league.by_summoner("kr", add1)[0]["tier"]
        except:
            summonerName = RiotWatcher(config[list(config.keys())[x]]).account.by_puuid("ASIA", participants_puuid[i])["gameName"]
            add1 = api.summoner.by_name("kr",summonerName)["id"]
            add = api.league.by_summoner("kr", add1)[0]["tier"]

        participants_rank.append(add)


    if (participants[0]["teamId"] == 100 and participants[0]["win"] == True) or (participants[0]["teamId"] != 100 and participants[0]["win"] != "Win"):
        Win = 1
    else:
        Win = 0

    Blue = []
    Red = []
    Ban = [0,0,0,0,0,0,0,0,0,0]
    K = matchinfo["info"]["teams"][0]["bans"]
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

    Tier = ["C","G", "M", "D", "P", "G", "S", "B"]
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
    Tier = ["C","GM", "M", "D", "P", "G", "S", "B"]
    Tier = Tier[int(Num_tier/Total_tier)]

    if Blue[0] == Blue[1]:
        continue

    with open("match_data_ban.csv", "a") as f:
        line = str([gameId]) + ","  + str(Ban) + "," + str(Blue) + "," + str(Red) + "," + str(participants_rank) + "," + str(participants_puuid)+","+ str([Tier]) + ","+ str([Win]) + "\n"
        f.write(line)
    
    #Comment out this if unneccessary
    print("check")

