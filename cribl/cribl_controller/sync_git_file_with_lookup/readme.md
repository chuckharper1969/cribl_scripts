[http://localhost:8000](http://localhost:8000)  with destinations in Cribl</br>
[sync_portal_destinations](https://github.com/chuckharper1969/scripts/tree/main/cribl/cribl_controller/sync_git_file_with_lookup/main.py)
Syncs lookup files from the Github repo location [project_documents/common/lookup_files](https://github.com/chuckharper1969/project_documents/tree/main/common/lookup_files)  with lookups in Cribl</br>
Note this is just a one way from Git to Cribl and no lookups are deleted in Cribl that are not in Git repo. This can be accomplished but this would make this repo the source of record for all lookups in Cribl unless specific exceptions are made or pattern matching exceptions.?

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
