import os
import json
import requests
import base64

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

##############################################################################
# Load config file
##############################################################################
def load_json_file(file_path):

    json_obj = None
    try:
        with open(file_path) as file_obj:
            json_obj = json.load(file_obj)
    except Exception as e:
        raise(f"Failed loading json file [{str(e)}]")

    return(json_obj)

##############################################################################
# Check if string is base64
##############################################################################
def isBase64(sb):
    try:
        if isinstance(sb, str):
            # If there's any unicode here, an exception will be thrown and the function will return false
            sb_bytes = bytes(sb, 'ascii')
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False

##############################################################################
# function to obfuscate the password used in json file
##############################################################################
def process_authentication_file(auth_file_path, encrypted_keys=["password", "token"]):
    credentials = {}
    json_config = load_json_file(auth_file_path)
    for env in json_config:
        if not env in credentials:
            credentials[env] = {}
        for app in json_config[env]:
            if not app in credentials[env]:
                credentials[env][app] = {}
            for key, value in json_config[env][app].items():
                unencrypted_value = value
                if key in encrypted_keys:
                    if isBase64(value):
                        unencrypted_value = base64.b64decode(value.encode("utf-8")).decode()
                    else:
                        json_config[env][app][key] = base64.b64encode(value.encode("utf-8")).decode()
                        
                credentials[env][app][key] = unencrypted_value
    
    json_object = json.dumps(json_config, indent=4)
    with open(auth_file_path, "w") as outfile:
        outfile.write(json_object)
    
    return credentials


##############################################################################
# Cribl Auth
##############################################################################
def auth(cribl_url, cribl_username, cribl_password):
    header = {
        'Accept': 'application/json', 
        'Content-Type': 'application/json'
    }
    data =  {
        "username": cribl_username,
        "password": cribl_password
    }

    endpoint = f"{cribl_url}/api/v1/auth/login"

    try:
        r = requests.post(endpoint, headers=header, json=data, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))

    return r.json()["token"]


##############################################################################
# cribl_get_outputs
##############################################################################
def cribl_get_outputs(cribl_url, cribl_group, cribl_token):

    header = {
        "Accept": "application/json", 
        "Authorization": f"Bearer {cribl_token}"
    }

    endpoint = f"{cribl_url}/api/v1/m/{cribl_group}/system/outputs"

    try:
        r = requests.get(endpoint, headers=header, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))
    
    return r.json()

def main():
    secret_json_file = os.path.join("C:\\Users\\email\\secret.json")
    credentials = process_authentication_file(secret_json_file)

    cribl_username = credentials["development"]["cribl_conn"]["username"]
    cribl_password = credentials["development"]["cribl_conn"]["password"]
    cribl_url = "http://cribl.maejer.lab:9000"
    cribl_worker_group = "default"

    ###########################################################################
    # Get Cribl Token
    ###########################################################################
    cribl_auth_token = auth(cribl_url, cribl_username, cribl_password)

    ###########################################################################
    # Get List of outputs from Cribl
    # GET /api/v1/system/outputs
    ###########################################################################
    cribl_output_items = cribl_get_outputs(cribl_url, cribl_worker_group, cribl_auth_token)
    print(cribl_output_items)

if __name__ == "__main__":
    main()