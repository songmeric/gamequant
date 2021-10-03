
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from riotwatcher import LolWatcher
"""
with open("game1.csv", "r") as f:
    game = f.read().split(", ")
f.close()
"""

api = LolWatcher("RGAPI-44afe150-15f8-4167-812f-f50a3df2f569")

versions = api.data_dragon.versions_for_region("kr")

champions_version = versions['n']['champion']

current_champ_list = api.data_dragon.champions(champions_version)

ChampConvert = {}
for i in current_champ_list["data"]:
    ChampConvert[current_champ_list["data"][i]["id"]] = current_champ_list["data"][i]["key"]

ChampConvert["Dr.Mundo"]=ChampConvert["DrMundo"]
ChampConvert["Rek'Sai"] =ChampConvert["RekSai"]
ChampConvert["Kog'Maw"] =ChampConvert["KogMaw"]
ChampConvert["Cho'Gath"]= ChampConvert["Chogath"]
ChampConvert["Kai'Sa"] =ChampConvert["Kaisa"]
ChampConvert["Kha'Zix"]=ChampConvert["Khazix"]
ChampConvert["Vel'Koz"]=ChampConvert["Velkoz"]
ChampConvert["LeBlanc"]=ChampConvert["Leblanc"]
print(ChampConvert)

Challenger = []
challenger = api.league.challenger_by_queue("kr",queue="RANKED_SOLO_5x5")["entries"]
grandmaster = api.league.grandmaster_by_queue("kr",queue="RANKED_SOLO_5x5")["entries"]
master = api.league.masters_by_queue("kr",queue="RANKED_SOLO_5x5")["entries"]

for i in challenger:
    Challenger.append(i["summonerName"])

for i in grandmaster:
    Challenger.append(i["summonerName"])

for i in master:
    Challenger.append(i["summonerName"])


url = "http://fow.kr/ranking#1"
headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

r = requests.get(url, headers = headers)
content = r.content
soup = BeautifulSoup(content, "html.parser")

#names = soup.find_all("tbody", id="r_out")
names = soup.find_all("table", class_ = "rank_ranking")

print(names)
GameId = []
Win = []

for i in range(len(Challenger)):
    url = "https://www.op.gg/summoner/userName="+Challenger[0]
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

    r = requests.get(url, headers = headers)
    content = r.content
    soup = BeautifulSoup(content, "html.parser")

    names = soup.find_all("div", class_="ChampionImage")
    win = soup.find_all("div", class_="GameResult")
    for i in win:
        if "Victory" in i.text.replace(" ", ""):
            Win.append(1)
        else:
            Win.append(0)

    gameId = soup.find_all("div", class_="GameItem")
    for i in gameId:
        GameId.append(i.get("data-game-id"))

    #print(names)
    Names = []
    for i, name in enumerate(names):
        x = name.text
        x = x.split("\n")

        if x[1] != "":
            Names.append(ChampConvert[x[1].replace(" ", "")])

    for i in range(len(GameId)):
        line = [[GameId[i]],
                [Names[i * 10], Names[i * 10 + 1], Names[i * 10 + 2], Names[i * 10 + 3], Names[i * 10 + 4]],
                [Names[i * 10 + 5], Names[i * 10 + 6], Names[i * 10 + 7], Names[i * 10 + 8], Names[i * 10 + 9]],
                [Win[i]]]
        print(str(line))
    """
    with open("gamedata.csv", "a") as f:
        for i in range(len(GameId)):
            line = [[GameId[i]], [Names[i*10],Names[i*10+1],Names[i*10+2],Names[i*10+3],Names[i*10+4]],[Names[i*10+5],Names[i*10+6],Names[i*10+7],Names[i*10+8],Names[i*10+9]],[Win[i]]]
            f.write(str(line))
    """

