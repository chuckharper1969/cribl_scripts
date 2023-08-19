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
        raise SystemError(str(e))
    
    return r.json()

##############################################################################
# Upload Lookup File
##############################################################################
def cribl_upload_lookup(cribl_url, cribl_group, cribl_token, lookup_name, content):
    json_obj = None

    headers = {
        "Content-Type": "text/csv", 
        "Authorization": f"Bearer {cribl_token}"
    }
    params = {
        "filename": lookup_name,
    }

    endpoint = f"{cribl_url}/api/v1/m/{cribl_group}/system/lookups"

    try:
        r = requests.put(endpoint, params=params, headers=headers, data=content)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemError(str(e))
    
    if "Unauthorized" in r.text:
        return json_obj, r.text
    
    try:
        json_obj = json.loads(r.text)
    except Exception as e:
        raise SystemError(str(e))

    return json_obj, "OK"

##############################################################################
# Cribl Create Lookup
##############################################################################
def cribl_create_lookup(cribl_url, cribl_token, cribl_group, lookup_obj):
    json_obj = None

    headers = {
        "Accept": "application/json", 
        "Authorization": f"Bearer {cribl_token}"
    }

    cribl_uri = f"{cribl_url}/api/v1/m/{cribl_group}/system/lookups"

    try:
        r = requests.post(cribl_uri, headers=headers, json=lookup_obj)
    except requests.exceptions.RequestException as e:
        print("ERROR: patch request %s [%s]" % (cribl_uri, str(e)))
        return json_obj
    
    if "Unauthorized" in r.text:
        print("ERROR: patch request %s [Invalid Token]" % (cribl_uri))
        return json_obj
    
    try:
        json_obj = json.loads(r.text)
    except:
        print("ERROR: put request %s [Invalid JSON returned]" % (cribl_uri))

    return json_obj

def cribl_update_lookup(cribl_url, cribl_token, cribl_group, tmp_filename, lookup_name):
    json_obj = None

    headers = {
        "Accept": "application/json", 
        "Authorization": f"Bearer {cribl_token}" 
    }
    json_data = {
        "id": lookup_name,
        "fileInfo": {
            "filename": tmp_filename,
        },
    }

    endpoint = f"{cribl_url}/api/v1/m/{cribl_group}/system/lookups/{lookup_name}"

    try:
        r = requests.patch(endpoint, headers=headers, json=json_data)
    except requests.exceptions.RequestException as e:
        return json_obj, str(e)
    
    if "Unauthorized" in r.text:
        return json_obj, r.text
    
    try:
        json_obj = json.loads(r.text)
    except:
        return json_obj, r.text

    return json_obj, "OK"

def git_get_contents(connection, repo_name, base_path):
    url = connection.get("url", "https://api.github.com")
    organization = connection.get("organization", "chuckharper1969")
    headers = connection.get("headers", {"Acccept": "application/vnd.github.v3+json"})
    verify = connection.get("verify", False)

    credentials = (connection["username"], connection["token"])

    # GET /repos/{owner}/{repo}/contents/{path}
    endpoint = f"{url}/repos/{organization}/{repo_name}/contents/{base_path}"

    #r.raise_for_status()
    try:
        response = requests.get(endpoint, auth=credentials, verify=verify, headers=headers)
    except requests.exceptions.RequestException as e:
        raise SystemExit(str(e))
    
    if not response.status_code == 200:
        raise SystemExit(response.content)
    
    try:
        json_obj = json.loads(response.content)
    except Exception as e:
        raise SystemExit(str(e))

    return json_obj


##############################################################################
# Loop through Cribl lookup files in Git and compare with what is in Cribl
# Update if neccessary
##############################################################################
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
    # Get List of lookups from Cribl
    # GET /api/v1/system/lookups
    ###########################################################################
    cribl_lookup_items = cribl_get_lookups(cribl_url, cribl_worker_group, cribl_auth_token)
    cribl_lookups = {}
    for item in cribl_lookup_items["items"]:
        cribl_lookups[item["id"]] = item["size"]

    # Get list of lookups in Git
    git_username = credentials["development"]["git_conn"]["username"]
    git_token = credentials["development"]["git_conn"]["token"]
    git_api_url = "https://api.github.com"
    git_org = "chuckharper1969"
    git_lookup_repo = "project_documents"
    git_lookup_base_path = "common/lookup_files"

    git_connection = {
        "username": credentials["development"]["git_conn"]["username"],
        "token": credentials["development"]["git_conn"]["token"]
    }
    json_obj = git_get_contents(git_connection, git_lookup_repo, git_lookup_base_path)

    git_lookups = {}
    for file_obj in json_obj:
        git_lookups[file_obj["name"]] = file_obj["size"]
    
    print(cribl_lookups)
    print(git_lookups)

    for lookup_name, size in git_lookups.items():
        if not lookup_name in cribl_lookups or size != cribl_lookups[lookup_name]:
            print(f"Adding {lookup_name}")
            ###########################################################################
            # Upload lookup file, Creates .tmp file when uploaded
            ###########################################################################
            json_obj = git_get_contents(git_connection, git_lookup_repo, f"{git_lookup_base_path}/{lookup_name}")
            #content = base64.b64decode(json_obj["content"].encode("utf-8")).decode().encode("utf-8")
            content = base64.b64decode(json_obj["content"].encode("utf-8")).decode().encode("utf-8")
            print(content)

            json_obj, message = cribl_upload_lookup(cribl_url, cribl_worker_group, cribl_auth_token, lookup_name, content)
            if json_obj == None or not "filename" in json_obj:
                print(f"Failed to upload file. [{message}]")
                continue
            tmp_filename = json_obj["filename"]

            # if the lookup is not in cribl it needs to be posted else it needs to be patched
            if not lookup_name in cribl_lookups:
                lookup_obj = {
                    "id": lookup_name,
                    "fileInfo": {
                        "filename": tmp_filename
                    }
                }
                json_obj = cribl_create_lookup(cribl_url, cribl_auth_token, cribl_worker_group, lookup_obj)
                print(json_obj)
            else:
                json_obj, message = cribl_update_lookup(cribl_url, cribl_auth_token, cribl_worker_group, tmp_filename, lookup_name)
                print(json_obj)
                if json_obj == None or not "items" in json_obj:
                    raise SystemExit("Failed to update file.")


if __name__ == "__main__":
    main()