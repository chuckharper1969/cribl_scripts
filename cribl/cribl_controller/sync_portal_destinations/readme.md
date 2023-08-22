
# sync_portal_destinations

Syncs destinations from [customer portal]([https://github.com/chuckharper1969/cribl_customer_portal/tree/main/cribl_portals](https://github.com/chuckharper1969/cribl_customer_portal/tree/main)) running at [http://localhost:8000](http://localhost:8000) with destinations in Cribl running at [http://cribl.maejer.lab:9000](http://cribl.maejer.lab:9000).

# execution
The script can be executed through cron or similar. The shorter the interval, the quicker changes are reflected in Cribl.

# secret.json
Requires a secret.json in the following format. The password is entered in plain-text but after execution of the script it will base64 encode the string. Not secure but more secure than plain-text.
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

# config.json
```
{
    "cribl_conn": {
        "url": "http://cribl.maejer.lab:9000",
        "group": "default"
    },
    "portal_conn": {
        "url": "http://127.0.0.1:8000"
    },
    "auth": {
        "secret_file_location": "C:\\Users\\email\\secret.json"
    },
    "logging": {
        "hec": {
            "host": "cribl-worker01.maejer.lab",
            "port": "8088",
            "proto": "http",
            "ssl_verify": false,
            "source": "sync_portal_destinations"
        },
        "level": 10
    },
    "templates": {
        "elastic_output_router": {
            "systemFields": [
                "cribl_pipe"
            ],
            "streamtags": [
                "elk",
                "elastic"
            ],
            "rules": [
            {
                "final": true,
                "filter": "true",
                "output": "devnull",
                "description": "default_description"
            }
            ],
            "type": "router",
            "id": "ELK_Outputs_Router"
        },
        "elastic_output": {
            "id": "###LABEL###",
            "systemFields": [
              "cribl_pipe"
            ],
            "streamtags": [],
            "loadBalanced": false,
            "concurrency": 5,
            "maxPayloadSizeKB": 4096,
            "maxPayloadEvents": 0,
            "compress": false,
            "rejectUnauthorized": false,
            "timeoutSec": 30,
            "flushPeriodSec": 1,
            "failedRequestLoggingMode": "none",
            "safeHeaders": [],
            "auth": {
              "disabled": false,
              "authType": "manual",
              "username": "###USERNAME###",
              "password": "###PASSWORD###"
            },
            "elasticVersion": "auto",
            "onBackpressure": "block",
            "useRoundRobinDns": false,
            "type": "elastic",
            "index": "'default'",
            "url": "###URL###"
        }
    }
}   
```
