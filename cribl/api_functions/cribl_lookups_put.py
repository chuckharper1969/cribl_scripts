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
    
    print("Success: %s" % json_obj)

if __name__ == "__main__":
    main()