from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.chrome.service import Service
from anticaptchaofficial.recaptchav2proxyless import *
import threading

t0 = time.time()
allocation = 15
with open('/home/ubuntu/gamequant/24.csv','r') as f:
    data = f.readlines()


def collect(start):
    global allocation
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")

    s = Service('/home/ubuntu/gamequant/chromedriver')
    browser = webdriver.Chrome(service=s, options=options)

    browser.get('https://developer.riotgames.com')
    end = start + allocation
    if end >= len(data):
        end = len(data)
    for k, i in enumerate(data[start:end]):
        try:
            i = i[:-1]
            # filling form
            id = i.split(',')[0]
            password = i.split(',')[1]
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
            # print(LolWatcher(new_api_key).summoner.by_name("kr", '방관탐')["puuid"])
            with open('/home/ubuntu/gamequant/api.csv', 'a') as f:
                f.writelines(new_api_key+','+i+'\n')
        except Exception as E:
            print('##########Error with', start, k, i, E)

Pros = []
if __name__ == "__main__":
    # change the value inside the range
    n = 4
    for i in range(n):
        print("Thread Started")
        p = threading.Thread(target=collect, args=(i*allocation,))
        Pros.append(p)
        p.start()

    for t in Pros:
        t.join()
    print(time.time()-t0)
