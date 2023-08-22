import os
import json
import requests
import base64
import logging
import sys
from splunk_hec_handler import SplunkHecHandler

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("sync_portal_destinations")
logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.DEBUG)

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
            # If there"s any unicode here, an exception will be thrown and the function will return false
            sb_bytes = bytes(sb, "ascii")
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
# Portal Auth
##############################################################################
def portal_auth(portal_connection, verify=False):
    header = {
        "Accept": "application/json", 
        "Content-Type": "application/json"
    }
    data =  {
        "username": portal_connection["username"],
        "password": portal_connection["password"]
    }

    endpoint = f"{portal_connection['url']}/api-token-auth/"

    try:
        r = requests.post(endpoint, headers=header, json=data, verify=verify)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))

    return r.json()["token"]

##############################################################################
# cribl_get_outputs
##############################################################################
def portal_destinations_get(portal_connection, portal_type):

    header = {
        "Accept": "application/json", 
        "Authorization": f"Token {portal_connection['token']}"
    }

    endpoint = f"{portal_connection['url']}/api/v1/{portal_type}/get/"
    
    try:
        r = requests.get(endpoint, headers=header, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))
    
    return r.json()

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
def cribl_get_outputs(cribl_connection):

    header = {
        "Accept": "application/json", 
        "Authorization": f"Bearer {cribl_connection['token'] }"
    }

    endpoint = f"{cribl_connection['url']}/api/v1/m/{cribl_connection['group']}/system/outputs"

    try:
        r = requests.get(endpoint, headers=header, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))
    
    return r.json()

##############################################################################
# cribl_update_destination
##############################################################################
def cribl_update_destination(cribl_connection, output_id, json_output):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {cribl_connection['token'] }"
    }

    endpoint = f"{cribl_connection['url']}/api/v1/m/{cribl_connection['group']}/system/outputs/{output_id}"

    try:
        r = requests.patch(endpoint, headers=headers, json=json_output, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))

    return r.json()

##############################################################################
# cribl_delete_destination
##############################################################################
def cribl_delete_destination(cribl_connection, output_id):
    headers = {
        "Accept": "application/json", 
        "Authorization": f"Bearer {cribl_connection['token'] }"
    }

    endpoint = f"{cribl_connection['url']}/api/v1/m/{cribl_connection['group']}/system/outputs/{output_id}"

    try:
        r = requests.delete(endpoint, headers=headers, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))
    
    return r.json()

##############################################################################
# cribl_add_destination
##############################################################################
def cribl_add_destination(cribl_connection, json_new_output):
    print(json_new_output)
    headers = {
        "Accept": "application/json", 
        "Authorization": f"Bearer {cribl_connection['token'] }"
    }

    endpoint = f"{cribl_connection['url']}/api/v1/m/{cribl_connection['group']}/system/outputs"

    try:
        r = requests.post(endpoint, headers=headers, json=json_new_output, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))

    return r.json()

##############################################################################
# -Pull a list of elastic destinations from a customer portal database accessible by API.
# -Compare list from portal with those in Cribl
# -Add any that do not exist; 
# -Remove any that exist that are no longer in portal
# -Update any notable fields that have changed in portal
# -cribl destinations that are involved in compare are distinguishable through streamtag of "criblauto-portal"
# - if this is not acceptable than an "automation prefix" can be applied to output_id
##############################################################################
def main():
    
    cwd = os.path.dirname(os.path.realpath(__file__))
    config_file = os.path.join(cwd, "config.json")
    try:
        config_json = load_json_file(config_file)
    except:
        raise SystemExit(f"Unable to read json file '{config_file}'")

    try:
        secret_json_file = config_json["auth"]["secret_file_location"]
        credentials = process_authentication_file(secret_json_file)
    except:
        raise SystemExit(f"Unable to process authentication file '{secret_json_file}'")

    logger.setLevel(logging.DEBUG)
    splunk_handler = SplunkHecHandler(config_json["logging"]["hec"]["host"],
                        credentials["development"]["splunk_hec"]["token"],
                        port=config_json["logging"]["hec"]["port"], 
                        proto=config_json["logging"]["hec"]["proto"], 
                        ssl_verify=config_json["logging"]["hec"]["ssl_verify"],
                        source=config_json["logging"]["hec"]["source"]
    )
    logger.addHandler(splunk_handler)
    

    logger.debug("Requesting cribl authorization token")
    cribl_conn = {
        "username": credentials["development"]["cribl_conn"]["username"],
        "password": credentials["development"]["cribl_conn"]["password"],
        "url": config_json["cribl_conn"]["url"],
        "group": config_json["cribl_conn"]["group"]
    }
    cribl_conn["token"] = auth(cribl_conn)
    
    logger.debug("Requesting portal authorization token")
    portal_conn = {
        "username": credentials["development"]["portal_conn"]["username"],
        "password": credentials["development"]["portal_conn"]["password"],
        "url": config_json["portal_conn"]["url"]
    }
    portal_conn["token"] = portal_auth(portal_conn)

    portal_destinations = portal_destinations_get(portal_conn, "elastic")
    cribl_destinations = cribl_get_outputs(cribl_conn)["items"]

    cribl_automated = []
    for cribl_destination in cribl_destinations:
        if not cribl_destination["type"] == "elastic":
            continue
        if not "criblauto-portal" in cribl_destination["streamtags"]:
            continue
        cribl_automated.append(cribl_destination)
    
    # find destinations that need to be updated
    logger.debug("Checking if destinations need to be updated")
    for portal_destination in portal_destinations:
        for existing_destination in cribl_automated:
            if portal_destination["title"] == existing_destination["id"]:
                # compare values
                modified = False
                if not existing_destination["auth"]["username"] == portal_destination["username"]:
                    existing_destination["auth"]["username"] = portal_destination["username"]
                    modified = True
                if not existing_destination["auth"]["password"] == portal_destination["password"]:
                    existing_destination["auth"]["password"] = portal_destination["password"]
                    modified = True
                if not existing_destination["url"] == portal_destination["url"]:
                    existing_destination["url"] = portal_destination["url"]
                    modified = True
                if modified == False:
                    continue
                logger.debug(f"Updating destination '{existing_destination['id']}'")
                result = cribl_update_destination(cribl_conn, existing_destination["id"], existing_destination)

    
    # find destinations that need to be added
    logger.debug("Checking if destinations need to be added")
    for portal_destination in portal_destinations:
        found = False
        for existing_destination in cribl_automated:
            if portal_destination["title"] == existing_destination["id"]:
                found = True
        if found == True:
            continue
        # Add destination to cribl
        json_obj = config_json["templates"]["elastic_output"].copy()
        json_obj["id"] = portal_destination["title"]
        json_obj["auth"]["username"] = portal_destination["username"]
        json_obj["auth"]["password"] = portal_destination["password"]
        json_obj["url"] = portal_destination["url"]
        json_obj["streamtags"].append("criblauto-portal")
        
        logger.debug(f"Adding destination {json_obj['id']}")
        result = cribl_add_destination(cribl_conn, json_obj)
    
    # find destinations that need to be removed
    logger.debug("Checking if destinations need to be removed")
    for existing_destination in cribl_automated:
        found = False
        for portal_destination in portal_destinations:
            if portal_destination["title"] == existing_destination["id"]:
                found = True
        if found == True:
            continue
        
        logger.debug(f"Removing destination {existing_destination['id']}")
        result = cribl_delete_destination(cribl_conn, existing_destination["id"])
    
    logger.debug("Finished")
    
if __name__ == "__main__":
    main()