import os
import json
import requests
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
# cribl_get_outputs
##############################################################################
def cribl_get_lookups(cribl_connection, verify=False):

    header = {
        "Accept": "application/json", 
        "Authorization": f"Bearer {cribl_connection['token']}" 
    }

    endpoint = f"{cribl_connection['url']}/api/v1/m/{cribl_connection['group']}/system/lookups"

    try:
        r = requests.get(endpoint, headers=header, verify=verify)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))
    
    return r.json()

##############################################################################
# Upload Lookup File
##############################################################################
def cribl_upload_lookup(cribl_connection, lookup_name, content, verify=False):
    json_obj = None

    headers = {
        "Content-Type": "text/csv", 
        "Authorization": f"Bearer {cribl_connection['token']}"
    }
    params = {
        "filename": lookup_name,
    }

    endpoint = f"{cribl_connection['url']}/api/v1/m/{cribl_connection['group']}/system/lookups"

    try:
        r = requests.put(endpoint, params=params, headers=headers, data=content)
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))
    
    if "Unauthorized" in r.text:
        raise SystemExit(r.text)
    
    try:
        json_obj = json.loads(r.text)
    except Exception as e:
        raise SystemExit(str(e))

    return json_obj


def cribl_update_lookup(cribl_connection, tmp_filename, lookup_name):
    json_obj = None

    headers = {
        "Accept": "application/json", 
        "Authorization": f"Bearer {cribl_connection['token']}" 
    }
    json_data = {
        "id": lookup_name,
        "fileInfo": {
            "filename": tmp_filename,
        },
    }

    endpoint = f"{cribl_connection['url']}/api/v1/m/{cribl_connection['group']}/system/lookups/{lookup_name}"

    try:
        r = requests.patch(endpoint, headers=headers, json=json_data)
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))
    
    if "Unauthorized" in r.text:
        raise SystemExit(r.text)
    
    try:
        json_obj = json.loads(r.text)
    except:
        raise SystemExit(str(e))

    return json_obj

##############################################################################
# Cribl Create Lookup
##############################################################################
def cribl_create_lookup(cribl_connection, tmp_filename):
    json_obj = None

    lookup_name = ".".join(tmp_filename.split(".")[:-2])
    lookup_obj = {
        "id": lookup_name,
        "fileInfo": {
            "filename": tmp_filename
        }
    }

    headers = {
        "Accept": "application/json", 
        "Authorization": f"Bearer {cribl_connection['token']}"
    }

    endpoint = f"{cribl_connection['url']}/api/v1/m/{cribl_connection['group']}/system/lookups"

    try:
        r = requests.post(endpoint, headers=headers, json=lookup_obj)
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

    lookup_dir = "C:\\Users\\email\\OneDrive\\Documents"
    lookup_name = "timezone2.csv"

    # grab content of local lookup file
    try:
        file_path = os.path.join(lookup_dir, lookup_name)
        with open(file_path, 'rb') as file_obj:
            file_content = file_obj.read()
    except Exception as e:
        return json_obj, str(e)
    
    # upload content of local lookup file
    json_obj = cribl_upload_lookup(cribl_conn, lookup_name, file_content)
    if json_obj == None or not "filename" in json_obj:
        raise SystemExit(f"Failed to upload file. [{json_obj}]")
    tmp_filename = json_obj["filename"]

    # get a list of lookups currently in Cribl
    lookups = cribl_get_lookups(cribl_conn)
    found_lookup = False
    for lookup in lookups["items"]:
        if lookup["id"] == lookup_name:
            found_lookup = True
    
    # If lookup was not found in the list of current lookups then Create the lookup instead of Updating
    if not found_lookup:
        json_obj = cribl_create_lookup(cribl_conn, tmp_filename)
        # {'items': [{'id': 'snakes_count_10.csv', 'size': 91}], 'count': 1}
        if json_obj == None or not "items" in json_obj:
            raise SystemExit("Failed to create lookup file.")
    # lookup already exists
    else:
        json_obj = cribl_update_lookup(cribl_conn, tmp_filename, lookup_name)
        # {'items': [{'id': 'snakes_count_10.csv', 'size': 91}], 'count': 1}
        if json_obj == None or not "items" in json_obj:
            raise SystemExit("Failed to update lookup file.")
    
    print("Success: %s" % json_obj)

if __name__ == "__main__":
    main()