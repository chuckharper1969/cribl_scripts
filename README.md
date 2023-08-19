# cribl_scripts

[sync_git_file_with_lookup](https://github.com/chuckharper1969/scripts/tree/main/cribl/cribl_controller/sync_git_file_with_lookup/main.py)
Syncs lookup files from the Github repo location [project_documents/common/lookup_files](https://github.com/chuckharper1969/project_documents/tree/main/common/lookup_files)  with lookups in Cribl


# secret.json
Some of the example scripts requires a secret.json in the following format. The password is entered in plain-text but after execution of the script it will base64 encode the string.
```
{
    "development": {
        "cribl_conn": {
            "username": "admin",
            "password": "VEhJU19XSUxMX05PVF9XT1JL"
        },
        "git_conn": {
            "username": "chuckharper1969",
            "token": "VEhJU19XSUxMX05PVF9XT1JL"
        },
        "splunk_conn": {
            "username": "charper",
            "password": "VEhJU19XSUxMX05PVF9XT1JL"
        }
    }
}
```
