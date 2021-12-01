from riotwatcher import LolWatcher
import threading
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.chrome.service import Service
from anticaptchaofficial.recaptchav2proxyless import *

###### DEALING WITH ERROR ######
# If there are too many 'error_puuid' printed, try one of these:
# (1) change match to match_v5 in when calling api
# (2) change match_v5 to match in when calling api
# (3) check whether the apis are valid uncommenting the section 'error_puuid(3)'


# to measure the time taken (comparing effectiveness of threading)
t0 = time.time()

# Initial settings

# number of api key used
num_api_key = 15
num_summoner = 9573
# reading files
with open('/home/ubuntu/gamequant/api.csv', 'r') as f:
    data = f.readlines()
print(data)

apis = []
idpw = []

for i in data:
    i = i.split(',')
    idpw.append(i[1:])
    apis.append(i[0])

with open("/home/ubuntu/gamequant/summoner_processed.csv") as f:
    names = f.readlines()

'''
for j, i in enumerate(apis):
    try:
        i = i[:-1]
        api = LolWatcher(i)
        print(j, i, api.summoner.by_name("kr", '방관탐')["puuid"])
    except:
        print(j, i, 'error')
'''



#API Collector
def api_collect(id, password):
    global allocation
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")

    s = Service('/home/ubuntu/gamequant/chromedriver')
    browser = webdriver.Chrome(service=s, options=options)

    browser.get('https://developer.riotgames.com')


    try:
        WebDriverWait(browser, 120).until(lambda x: x.find_element(By.XPATH,
                                                                   '//*[@id="site-navbar-collapse"]/ul[2]/li/a'))
        buttons = browser.find_elements(By.XPATH, '//*[@id="site-navbar-collapse"]/ul[2]/li/a')
        for button in buttons:
            button.click()

        WebDriverWait(browser,120).until(lambda x: x.find_element(By.XPATH, '/html/body/div/div/div/div[2]/div/div/div[2]/div/div/div/div[1]/div/input'))
        browser.find_element(By.XPATH, '/html/body/div/div/div/div[2]/div/div/div[2]/div/div/div/div[1]/div/input').send_keys(id)
        browser.find_element(By.XPATH, '/html/body/div/div/div/div[2]/div/div/div[2]/div/div/div/div[2]/div/input').send_keys(password)

        # a = ActionChains(browser)
        browser.find_element(By.XPATH, '/html/body/div/div/div/div[2]/div/div/button').click()
        # WebDriverWait(browser, 10).until(EC.frame_to_be_available_and_switch_to_it((By.CSS_SELECTOR, "iframe[name^='a-'][src^='https://www.google.com/recaptcha/api2/anchor?']")))
        # WebDriverWait(browser, 10).until(EC.element_to_be_clickable((By.XPATH, "//span[@id='recaptcha-anchor']"))).click()

        # token = browser.find_element(By.XPATH, '/html/body/input').get_attribute('value')
        # print(token)
        # wait for "solved" selector to come up
        g_response = 0
        while g_response == 0:
            sitekey = "6LcOGicUAAAAAI8bWJ6IYXt5teyzO-t4aKskR5Iz"
            solver = recaptchaV2Proxyless()
            solver.set_verbose(1)
            solver.set_key('9464688d7256ea52ff2b64fb407f6c73')
            solver.set_website_url('https://developer.riotgames.com/')
            solver.set_website_key(sitekey)

            g_response = solver.solve_and_return_solution()
            print(g_response)

        browser.execute_script(f'document.getElementById("g-recaptcha-response").innerHTML="{g_response}";')
        browser.find_element(By.XPATH, '/html/body/div[2]/div/form/div[3]/div/div[3]/div[2]/div[2]/input').click()

        new_api_key = browser.find_element(By.ID, 'apikey').get_attribute('value')
        browser.get('https://developer.riotgames.com/logout')


        print(new_api_key)
        return new_api_key
    except Exception as E:
        print('##########Error with', E)


def collect(api_start, name_start, name_end):
    global apis, names
    # Making Dictionary to put api_keys
    config={}
    for i in range(num_api_key):
        config[str(i)] =''


    # Setting initial values (api setting, summoner name setting)
    api_end = api_start + num_api_key
    for i, api in enumerate(apis[api_start:api_end]):
        try:
            Api = LolWatcher(api)
            answer = Api.summoner.by_name("kr", '방관탐')["puuid"]
            config[list(config.keys())[i]] = api
        except:
            print('API_ERROR',i,api)
            print(idpw[i+api_start])
            Id, pwd = idpw[i+api_start][0], idpw[i+api_start][1]
            temp_api = api_collect(Id, pwd[:-1])
            print(temp_api)
            config[list(config.keys())[i]] = temp_api

    api = LolWatcher(config['0'])
    num = 0
    api_call = 0
    thread_num = int(api_start/num_api_key)
    if name_end > len(names):
        name_end = len(names)

    # MAIN LOOP
    for k, i in enumerate(names[name_start:name_end]):
        x = 0
        # 23h stop
        '''
        if time.time() - t1 > 43200:
            while text != 'A':
                t1 = time.time()
                print(api_start / num_api_key, k, i)
                text = input(f'{thread_num}th Thread 23h: Press "A" to continue\n')
            text = 'B'
            print(f'{thread_num}th 23h Thread started')
            with open('api.csv') as f:
                apis = f.readlines()
            print(apis)
            for i, api in enumerate(apis[api_start:api_end]):
                try:
                    Api = LolWatcher(api)
                    answer = Api.summoner.by_name("kr", '방관탐')["puuid"]
                    config[list(config.keys())[i]] = api
                except:
                    print('API_ERROR', i, api)
        '''
        summoner_name = i[:-1]
        while True:
            try:
                if (api_call < 99):
                    answer = api.summoner.by_name("kr", '방관탐')["puuid"]
                    api_call += 1
                    break
                elif (api_call >= 99):
                    num += 1
                    x = num % len(list(config.keys()))
                    api = LolWatcher(config[list(config.keys())[x]])
                    api_call = 0
                    answer = api.summoner.by_name("kr", '방관탐')["puuid"]
                    print(f"{thread_num}, api_swap")
                    break
            except:
                Id, pwd = idpw[api_start + x][0], idpw[api_start + x][1]
                temp_api = api_collect(Id, pwd[:-1])
                config[list(config.keys())[x]] = temp_api
                num += 1
                x = num % len(list(config.keys()))
                api = LolWatcher(config[list(config.keys())[x]])
                api_call = 0

        try:
            if(api_call < 99):
                summoner_id = api.summoner.by_name("kr", summoner_name)["puuid"]
                print(summoner_id)
                api_call += 1
            elif(api_call >= 99):
                num += 1
                x = num % len(list(config.keys()))
                api = LolWatcher(config[list(config.keys())[x]])
                api_call = 0
                summoner_id = api.summoner.by_name("kr", summoner_name)["puuid"]
                api_call += 1
                print(f"{thread_num}, api_swap")

            start = 0
            matchlist = []
            while True:
                if (api_call < 99):
                    matchtemp = api.match_v5.matchlist_by_puuid("ASIA", summoner_id, queue=420, start=start, count=100)
                    matchlist = matchlist + matchtemp
                    api_call += 1
                    start += 100
                    if len(matchtemp) == 0:
                        break
                elif (api_call >= 99):
                    num += 1
                    x = num % len(list(config.keys()))
                    api = LolWatcher(config[list(config.keys())[x]])
                    api_call = 0
                    matchtemp = api.match_v5.matchlist_by_puuid("ASIA", summoner_id, queue=420, start=start, count=100)
                    matchlist = matchlist + matchtemp
                    start += 100
                    api_call += 1
                    print(f"{thread_num}, api_swap")
                    if len(matchtemp) == 0:
                        break
            print(len(matchlist))

        except:
            print(f"error_puuid{thread_num}", i)
            continue


        # Extracting matchinfo from the games in matchlist
        for gameId in matchlist:
            while(True):
                try:
                    if(api_call < 99):
                        matchinfo = api.match_v5.by_id("ASIA", gameId)
                        api_call += 1
                    elif(api_call >= 99):
                        num += 1
                        x = num % len(list(config.keys()))
                        api = LolWatcher(config[list(config.keys())[x]])
                        api_call = 0
                        matchinfo = api.match_v5.by_id("ASIA", gameId)
                        api_call += 1
                        print(f"{thread_num}, api_swap")


                    if matchinfo["info"]["queueId"] != 420:
                        # print(matchinfo["info"]["queueId"])
                        # print(num)
                        continue

                    participants = matchinfo["info"]["participants"]
                    # print(participants[0]["teamId"])
                    # print(participants[0]["win"])

                    if (participants[0]["teamId"] == 100 and participants[0]["win"] == True) or (
                            participants[0]["teamId"] != 100 and participants[0]["win"] != True):
                        Win = 1
                    else:
                        Win = 0

                    Blue = []
                    Red = []
                    Ban = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    K = matchinfo["info"]["teams"][0]["bans"]
                    # print(K)
                    for i in K:
                        Ban[i["pickTurn"] - 1] = i["championId"]

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

                    with open("/home/ubuntu/gamequant/match_data_ban.csv", "a") as f:
                        line = str([gameId]) + ","  + str(Ban) + "," + str(Blue) + "," + str(Red) + "," + str([Win]) + "\n"
                        f.write(line)

                    with open("/home/ubuntu/gamequant/match_data_ban_total.csv", 'a') as f:
                        line = str(matchinfo) + '\n'
                        f.write(line)

                    # print(gameId)
                    # print(api_call)
                    break
                except Exception as e:
                    print(f"error pass{thread_num}",num, e)
                    while True:
                        try:
                            if (api_call < 99):
                                answer = api.summoner.by_name("kr", '방관탐')["puuid"]
                                api_call += 1
                                break
                            elif (api_call >= 99):
                                num += 1
                                x = num % len(list(config.keys()))
                                api = LolWatcher(config[list(config.keys())[x]])
                                api_call = 0
                                answer = api.summoner.by_name("kr", '방관탐')["puuid"]

                                print(f"{thread_num}, api_swap")
                                break
                        except:
                            Id, pwd = idpw[api_start + x][0], idpw[api_start + x][1]
                            temp_api = api_collect(Id, pwd[:-1])
                            config[list(config.keys())[x]] = temp_api
                            num += 1
                            x = num % len(list(config.keys()))
                            api = LolWatcher(config[list(config.keys())[x]])
                            api_call = 0

        print('Success', thread_num, k, i)
    print(f'Finished {thread_num}')


Pros = []
if __name__ == "__main__":
    # change the value inside the range
    n = len(apis) // num_api_key
    for i in range(n):
        print("Thread Started")
        p = threading.Thread(target=collect, args=(i*num_api_key, i*num_summoner, (i+1)*num_summoner,))
        Pros.append(p)
        p.start()

    for t in Pros:
        t.join()
    print(time.time()-t0)
