import os
import json
import requests
import base64

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

def search_repo(api_url, username, token, search, repo_name, org):
    headers = {
        "Acccept": "application/vnd.github.v3+json"
    }
    query_string = "q=%s+in:file+repo:%s/%s" % (search, org, repo_name)
    url = "%s/search/code?%s" % (api_url, query_string)
    res = requests.get(url, auth=(username, token), verify=False, headers=headers)
    content = res.content
    json_ret = json.loads(content)
    return json_ret


def main():
    GIT_API_URL = "https://api.github.com"
    GIT_ORG = "chuckharper1969"
    GIT_TOKEN = "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"
    headers = {
        "Acccept": "application/vnd.github.v3+json"
    }
    # GET /repos/{owner}/{repo}/contents/{path}
    endpoint = "https://api.github.com/repos/chuckharper1969/project_documents/contents/splunk/indexers.csv"

    response = requests.get(endpoint, auth=("chuckharper1969", GIT_TOKEN), verify=False, headers=headers)
    json_obj = json.loads(response.content)
    
    file_sha = json_obj["sha"]

    # GET /repos/{owner}/{repo}/git/blobs/{file_sha}
    endpoint = f"https://api.github.com/repos/chuckharper1969/project_documents/git/blobs/{file_sha}"

    response = requests.get(endpoint, auth=("chuckharper1969", GIT_TOKEN), verify=False, headers=headers)
    json_obj = json.loads(response.content)
    
    base64_content = json_obj["content"]

    content_string = base64.b64decode(base64_content)
    contents = content_string.decode('utf-8').split('\n')
    print(contents)


if __name__ == "__main__":
    main()