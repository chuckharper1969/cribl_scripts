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

def cribl_get_route_by_id(cribl_connection, item_id, verify=False):
    json_obj = None

    header = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {cribl_connection['token']}" 
    }

    endpoint = f"{cribl_connection['url']}/api/v1/m/{cribl_connection['group']}/routes/{item_id}"

    try:
        r = requests.get(endpoint, headers=header, verify=verify)
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))
    
    if "Unauthorized" in r.text:
        raise SystemExit(r.text)
    
    try:
        json_obj = json.loads(r.text)
    except Exception as e:
        raise SystemExit(str(e))

    return json_obj

def cribl_update_route(cribl_connection, item_id, route_obj, verify=False):
    json_obj = None

    header = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {cribl_connection['token']}" 
    }

    endpoint = f"{cribl_connection['url']}/api/v1/m/{cribl_connection['group']}/routes/{item_id}"

    try:
        r = requests.patch(endpoint, headers=header, json=route_obj, verify=verify)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))
    
    if "Unauthorized" in r.text:
        raise SystemExit(r.text)
    
    try:
        json_obj = json.loads(r.text)
    except Exception as e:
        raise SystemExit(str(e))

    return json_obj

def main():

    cribl_conn = {
        "username": "admin",
        "password": getpass.getpass("Enter Password: "),
        "url": "http://cribl.maejer.lab:9000",
        "group": "default"
    }
    cribl_conn["token"] = auth(cribl_conn)

    item_target_id = "default" # will always be default as it pertains to routes?
    route_target_name = "route_test_source" #name of the route to be modified
    new_filter = "__inputId=='splunk_hec:splunk_HEC_8088' && (app_id=='app01' || app_id=='app02')"
    #new_filter = "true"
    
    # retreive route
    json_obj = cribl_get_route_by_id(cribl_conn, item_target_id)
    if json_obj == None or not json_obj["count"] == 1:
        print(f"Failed to retrieve route '{route_target_name}'. [{json_obj}]")
    
    routes_obj = json_obj["items"][0]

    # modify route
    routes = []
    for route_obj in routes_obj["routes"]:
        if route_obj["name"] == route_target_name:
            route_obj["filter"] = new_filter
        routes.append(route_obj)
    
    routes_obj["routes"] = routes

    # update routes
    update_obj = cribl_update_route(cribl_conn, item_target_id, routes_obj)
    print(update_obj)

if __name__ == "__main__":
    main()