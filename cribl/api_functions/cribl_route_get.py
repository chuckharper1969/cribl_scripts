import requests
import json
import getpass

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

##############################################################################
# Cribl Auth
##############################################################################
def auth(cribl_connection, verify=False):
    header = {
        "Accept": "application/json", 
        "Content-Type": "application/json"
    }
    data =  {
        "username": cribl_connection["username"],
        "password": cribl_connection["password"]
    }

    endpoint = f"{cribl_connection['url']}/api/v1/auth/login"

    try:
        r = requests.post(endpoint, headers=header, json=data, verify=verify)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))

    return r.json()["token"]


##############################################################################
# cribl_get_routes: 
##############################################################################
def cribl_get_routes(cribl_connection):
    json_obj = None

    header = {
        "accept": "application/json", 
        "Authorization": f"Bearer {cribl_connection['token']}" 
    }

    endpoint = f"{cribl_connection['url']}/api/v1/m/{cribl_connection['group']}/routes"

    try:
        r = requests.get(endpoint, headers=header, verify=False)
    except requests.exceptions.RequestException as e:
        print("ERROR: get request %s [%s]" % (endpoint, str(e)))
        return json_obj
    
    if "Unauthorized" in r.text:
        print("ERROR: get request %s [Invalid Token]" % (endpoint))
        return json_obj

    try:
        json_obj = json.loads(r.text)
    except:
        print("ERROR: get request %s [Invalid JSON returned]" % (endpoint))
        return json_obj

    return json_obj

def main():
    cribl_conn = {
        "username": "admin",
        "password": getpass.getpass("Enter Password: "),
        "url": "http://cribl.maejer.lab:9000",
        "group": "default"
    }
    cribl_conn["token"] = auth(cribl_conn)

    # Get List of outputs from Cribl
    cribl_routes = cribl_get_routes(cribl_conn)
    print(cribl_routes)

if __name__ == "__main__":
    main()