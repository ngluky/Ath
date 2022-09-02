import json , os
import requests, sys , re , pickle
import requests.cookies
import typing

# command
    # login
        # user|pass|remwber|path cookie
    # get from cookie
        # path cookie

def login(passw:str,user:str,pathCookie:str = None) -> dict:
    se = GetCookie()
    data = {
        "language": "en_US",
        "password": passw,
        # "region": null,
        "type": "auth",
        "username": user
    }
    url = 'https://auth.riotgames.com/api/v1/authorization/'
    headers = { 

    }
    try:
        r = se.put(url, json= data, headers=headers)
        data = r.json()
        data_return["isSu"] = True
        data_return["err_mess"] = None
        data_return["data"] = Get_AccessToken_Entitlements_Token(data)

        
        if (not os.path.exists(pathCookie.replace(os.path.basename(pathCookie) , '')) and os.path.basename(pathCookie) != pathCookie):
            os.makedirs(pathCookie.replace(os.path.basename(pathCookie) , ''))


        if (pathCookie):
            with open(pathCookie, 'wb') as f:
                pickle.dump(se.cookies, f)

        return data_return
    except NameError as e:
        data_return["isSu"] = False
        data_return["err_mess"] = "Login fail"
        data_return["data"] = None  
        return data_return      


def Get_AccessToken_Entitlements_Token(data:dict) -> dict:
    pattern = re.compile('access_token=((?:[a-zA-Z]|\d|\.|-|_)*).*id_token=((?:[a-zA-Z]|\d|\.|-|_)*).*expires_in=(\d*)')
    data = pattern.findall(data['response']['parameters']['uri'])[0]
    access_token = data[0]

    headers = {
        'Authorization': f'Bearer {access_token}',
    }

    r = requests.post('https://entitlements.auth.riotgames.com/api/token/v1', headers=headers, json={})
    data = r.json()
    
    data_return = {
        "X-Riot-Entitlements-JWT" : data['entitlements_token'],
        "Authorization": f'Bearer {access_token}'
    }

    return data_return

    

def GetCookie(PathCooke : str = "") -> typing.Union[dict, requests.Session]:
    url = 'https://auth.riotgames.com/api/v1/authorization/'
    se = requests.Session()
    if (os.path.exists(PathCooke)):
        with open(PathCooke, 'rb') as f:
            se.cookies.update(pickle.load(f))
    data = {
        "client_id": "ritoplus",
        "nonce": "nuckles",
        "redirect_uri": "http://localhost/redirect",
        "response_type": "token id_token"
    }

    data

    headers = {

    }
    res = se.post(url, json= data , headers=headers)
    conten = res.json()
    if conten['type']  == "response":
        data_return["isSu"] = True
        data_return["err_mess"] = None
        data_return["data"] = Get_AccessToken_Entitlements_Token(conten)
        return data_return
    elif conten['type'] == 'auth':
        return se
    else:
        data_return["isSu"] = False
        data_return["err_mess"] = "Type req not math"
        data_return["data"] = None  
        return data_return      

# command
    # login
        # user|pass|path cookie
    # get from cookie
        # path cookie

def Main():
    data_return = {
        "isSu" : False,
        "err_mess" : "",
        "data": {
            "X-Riot-Entitlements-JWT" : None,
            "Authorization": None
        }
    }
    arg = sys.argv
    # print(arg)
    try:
        if arg[1] == "login":
            user = arg[2]
            passw = arg[3]
            pathCookie = arg[4]
            # print(user , passw , pathCookie)
            data_return = login(
                passw=passw,
                user=user,
                pathCookie=pathCookie
            )
        elif arg[1] == "get":
            pathCookie = arg[2]
            data_return = GetCookie(pathCookie)
        else:
            data_return["isSu"] = False
            data_return["err_mess"] = "Command fail"
            data_return["data"] = None 
    except Exception as e:
        data_return["isSu"] = False
        data_return["err_mess"] = str(e)
        data_return["data"] = None

    print(json.dumps(data_return))

data_return = {
    "isSu" : False,
    "err_mess" : "",
    "data": {
        "X-Riot-Entitlements-JWT" : None,
        "Authorization": None
    }
}

Main()