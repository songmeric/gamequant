import json
import champion_scraper

with open('champions.json') as json_file:
    json_data = json.load(json_file)
    champion_data = json_data["data"]
    champion_names = list(champion_data.keys())
    champion_names.remove("Neeko")
    champion_names.remove("Skarner")
    champion_names.remove("Vex")
    final_data = {} #Nested dictionary of: Champion name: { 'key': championID , 'lane': lanes }
    lane_data = champion_scraper.get_data()
    top_champions_primary = []
    jug_champions_primary = []
    mid_champions_primary = []
    adc_champions_primary = []
    sup_champions_primary = []
    top_champions_secondary = []
    jug_champions_secondary = []
    mid_champions_secondary = []
    adc_champions_secondary = []
    sup_champions_secondary = []

    ChampInttoName = {}
    for i in champion_names:
        champion_id = champion_data[i]['key']
        ChampInttoName[champion_id] = i

    for i in champion_names:
        champion_id = champion_data[i]['key']
        final_data[i] = {'key': champion_id, 'lane': lane_data[i]}

    for key, value in final_data.items():
        if value['lane'][0] == "T" and "Top" in value['lane']:
            top_champions_primary.append(value['key'])
        elif value['lane'][0] == "J" and "Jungle" in value['lane']:
            jug_champions_primary.append(value['key'])
        elif value['lane'][0] == "M" and "Middle" in value['lane']:
            mid_champions_primary.append(value['key'])
        elif value['lane'][0] == "B" and "Bottom" in value['lane']:
            adc_champions_primary.append(value['key'])
        elif value['lane'][0] == "S" and "Support" in value['lane']:
            sup_champions_primary.append(value['key'])

    for key, value in final_data.items():
        if value['lane'][0] != "T" and "Top" in value['lane']:
            top_champions_secondary.append(value['key'])
    for key, value in final_data.items():
        if value['lane'][0] != "J" and "Jungle" in value['lane']:
            jug_champions_secondary.append(value['key'])
    for key, value in final_data.items():
        if value['lane'][0] != "M" and "Middle" in value['lane']:
            mid_champions_secondary.append(value['key'])
    for key, value in final_data.items():
        if value['lane'][0] != "B" and "Bottom" in value['lane']:
            adc_champions_secondary.append(value['key'])
    for key, value in final_data.items():
        if value['lane'][0] != "S" and "Support" in value['lane']:
            sup_champions_secondary.append(value['key'])

def ChampName(thing):
    List = []
    for i in thing:
        List.append(ChampInttoName[i])
    return List

'''
print(final_data['Sett']['key'])
print("Top_Primary:")
print(top_champions_primary)
print(ChampName(top_champions_primary))
print("Jug_Primary:")
print(jug_champions_primary)
print(ChampName(jug_champions_primary))
print("Mid_Primary:")
print(mid_champions_primary)
print(ChampName(mid_champions_primary))
print("ADC_Primary:")
print(adc_champions_primary)
print(ChampName(adc_champions_primary))
print("Sup_Primary:")
print(sup_champions_primary)
print(ChampName(sup_champions_primary))
print("\n")
print("Top_Secondary:")
print(top_champions_secondary)
print(ChampName(top_champions_secondary))
print("Jug_Secondary:")
print(jug_champions_secondary)
print(ChampName(jug_champions_secondary))
print("Mid_Secondary:")
print(mid_champions_secondary)
print(ChampName(mid_champions_secondary))
print("ADC_Secondary:")
print(adc_champions_secondary)
print(ChampName(adc_champions_secondary))
print("Sup_Secondary:")
print(sup_champions_secondary)
print(ChampName(sup_champions_secondary))
'''

lenT = int(len(top_champions_secondary)/3)
T = top_champions_primary[:7-lenT] + top_champions_secondary[:lenT+1]

lenJ = int(len(jug_champions_secondary)/3)
J = jug_champions_primary[:7-lenT] + jug_champions_secondary[:lenJ+1]

lenM = int(len(mid_champions_secondary)/3)
M = mid_champions_primary[:7-lenM] + mid_champions_secondary[:lenM+1]

lenA = int(len(adc_champions_secondary)/2)
A = adc_champions_primary[:7-lenA] + adc_champions_secondary[:lenA+1]

lenS = int(len(sup_champions_secondary)/2)
S = sup_champions_primary[:7-lenS] + sup_champions_secondary[:lenS+1]

print(len(T), len(J), len(M), len(A), len(S))

import itertools
import numpy as np

'''
T = [1,2]
J = [2, 3]
M = [4,5]
A = [6,7]
S = [1,8]
'''

List = list(itertools.product(T,J,M,A,S))
for i in List:
    if len(i) != len(set(i)):
        List.remove(i)

Data = list(itertools.combinations(List,2))
for i in range(len(Data)):
    Data[i]=list(Data[i])
    Data[i][0] = list(Data[i][0])
    Data[i][1] = list(Data[i][1])
    Data[i].append(list(np.random.uniform(0.4,0.6,1)))

print(Data)
