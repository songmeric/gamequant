
import requests
from bs4 import BeautifulSoup
import re

url = "https://www.op.gg/champion/statistics"
headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
r = requests.get(url, headers = headers)
content = r.content
soup = BeautifulSoup(content, "lxml")
top_champions = soup.find(class_="champion-trend-tier-TOP").find_all('div', class_="champion-index-table__name")
top_champ_pref = soup.find(class_='champion-trend-tier-TOP').find_all(class_="champion-index-table__position")
jug_champions = soup.find(class_="champion-trend-tier-JUNGLE").find_all('div', class_="champion-index-table__name")
jug_champ_pref = soup.find(class_='champion-trend-tier-JUNGLE').find_all(class_="champion-index-table__position")
mid_champions = soup.find(class_="champion-trend-tier-MID").find_all('div', class_="champion-index-table__name")
mid_champ_pref = soup.find(class_='champion-trend-tier-MID').find_all(class_="champion-index-table__position")
adc_champions = soup.find(class_="champion-trend-tier-ADC").find_all('div', class_="champion-index-table__name")
adc_champ_pref = soup.find(class_='champion-trend-tier-ADC').find_all(class_="champion-index-table__position")
sup_champions = soup.find(class_="champion-trend-tier-SUPPORT").find_all('div', class_="champion-index-table__name")
sup_champ_pref = soup.find(class_='champion-trend-tier-SUPPORT').find_all(class_="champion-index-table__position")
data = {}
option = ''

def get_data():
    for i, name in enumerate(top_champions):
        preferences = top_champ_pref[i].text
        preferences = re.sub('\n', '', preferences)
        preferences = re.sub('\t', '', preferences)

        data[name.text.replace(" ","").replace("'","").replace("ChoGath","Chogath").replace(".","").replace("KaiSa","Kaisa").replace("KhaZix","Khazix").replace("LeBlanc","Leblanc").replace("Wukong","MonkeyKing").replace("Nunu&Willump","Nunu").replace("VelKoz", "Velkoz")] = preferences
    for i, name in enumerate(jug_champions):
        preferences = jug_champ_pref[i].text
        preferences = re.sub('\n', '', preferences)
        preferences = re.sub('\t', '', preferences)

        data[name.text.replace(" ","").replace("'","").replace("ChoGath","Chogath").replace(".","").replace("KaiSa","Kaisa").replace("KhaZix","Khazix").replace("LeBlanc","Leblanc").replace("Wukong","MonkeyKing").replace("Nunu&Willump","Nunu").replace("VelKoz", "Velkoz")] = preferences
    for i, name in enumerate(mid_champions):
        preferences = mid_champ_pref[i].text
        preferences = re.sub('\n', '', preferences)
        preferences = re.sub('\t', '', preferences)

        data[name.text.replace(" ","").replace("'","").replace("ChoGath","Chogath").replace(".","").replace("KaiSa","Kaisa").replace("KhaZix","Khazix").replace("LeBlanc","Leblanc").replace("Wukong","MonkeyKing").replace("Nunu&Willump","Nunu").replace("VelKoz", "Velkoz")] = preferences

    for i, name in enumerate(adc_champions):
        preferences = adc_champ_pref[i].text
        preferences = re.sub('\n', '', preferences)
        preferences = re.sub('\t', '', preferences)

        data[name.text.replace(" ","").replace("'","").replace("ChoGath","Chogath").replace(".","").replace("KaiSa","Kaisa").replace("KhaZix","Khazix").replace("LeBlanc","Leblanc").replace("Wukong","MonkeyKing").replace("Nunu&Willump","Nunu").replace("VelKoz", "Velkoz")] = preferences
    for i, name in enumerate(sup_champions):
        preferences = sup_champ_pref[i].text
        preferences = re.sub('\n', '', preferences)
        preferences = re.sub('\t', '', preferences)

        data[name.text.replace(" ","").replace("'","").replace("ChoGath","Chogath").replace(".","").replace("KaiSa","Kaisa").replace("KhaZix","Khazix").replace("LeBlanc","Leblanc").replace("Wukong","MonkeyKing").replace("Nunu&Willump","Nunu").replace("VelKoz", "Velkoz")] = preferences

    return data

if __name__ == "__main__":

    print(get_data())
