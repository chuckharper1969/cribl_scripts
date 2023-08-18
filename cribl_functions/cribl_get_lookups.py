import os, sys
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
        raise("Failed opening json file [%s]" % str(e))

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

    endpoint = "api/v1/auth/login"
    cribl_uri = "%s/%s" % (cribl_url, endpoint)

    try:
        r = requests.post(cribl_uri, headers=header, json=data, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        sys.exit("ERROR: %s" % str(e))

    return r.json()["token"]


##############################################################################
# cribl_get_outputs
##############################################################################
def cribl_get_lookups(cribl_url, cribl_group, cribl_token):

    header = {
        'Accept': 'application/json', 
        'Authorization': 'Bearer ' + cribl_token 
    }

    endpoint = f"api/v1/m/{cribl_group}/system/lookups"
    cribl_uri = "%s/%s" % (cribl_url, endpoint)

    try:
        r = requests.get(cribl_uri, headers=header, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(r.text)
        sys.exit("ERROR: %s" % str(e))
    
    return r.json()

def main():
    cwd = os.path.dirname(os.path.realpath(__file__))

    json_file_config = os.path.join(cwd, "config.json")
    json_config = load_json_file(json_file_config)

    cribl_url = json_config["cribl_conn"]["url"]
    cribl_username = json_config["cribl_conn"]["username"]
    cribl_password_encrypted = json_config["cribl_conn"]["password"]
    cribl_worker_group = json_config["worker_group"]

    if isBase64(cribl_password_encrypted):
        cribl_password = base64.b64decode(cribl_password_encrypted.encode("utf-8")).decode()
    else:
        # modify config.json
        cribl_password = cribl_password_encrypted
        json_config["cribl_conn"]["password"] = base64.b64encode(cribl_password_encrypted.encode("utf-8")).decode()
        json_object = json.dumps(json_config, indent=4)
        with open(json_file_config, "w") as outfile:
            #json.dump(json_object, outfile)
            outfile.write(json_object)

    ###########################################################################
    # Get Cribl Token
    ###########################################################################
    cribl_auth_token = auth(cribl_url, cribl_username, cribl_password)

    ###########################################################################
    # Get List of lookups from Cribl
    # GET /api/v1/system/lookups
    ###########################################################################
    cribl_lookup_items = cribl_get_lookups(cribl_url, cribl_worker_group, cribl_auth_token)
    print(cribl_lookup_items["items"])

if __name__ == "__main__":
    main()