
#[sync_portal_destinations](https://github.com/chuckharper1969/scripts/tree/main/cribl/cribl_controller/sync_git_file_with_lookup/main.py)
Syncs destinations from [customer portal](https://github.com/chuckharper1969/cribl_customer_portal/tree/main/cribl_portals) running at [http://localhost:8000](http://localhost:8000) with destinations in Cribl running at [http://cribl.maejer.lab:9000](http://cribl.maejer.lab:9000).

# secret.json
Requires a secret.json in the following format. The password is entered in plain-text but after execution of the script it will base64 encode the string.
```
{
    "development": {
        "cribl_conn": {
            "username": "admin",
            "password": "xUGsdgfsaeEA="
        },
        "portal_conn": {
            "username": "chuckharper",
            "password": "xUGsdgfsaeEA="
        }
    }
}
```
