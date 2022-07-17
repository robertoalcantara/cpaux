# cpaux
## Checkpoint firewall API helper

Checkpoint management API is a bit tricky to get the info organized as in "smart console".  Management API v1.8.

This project connects to management server and build a easily readable json output from access rules in specific rulebase. Useful to let devops team aware about the current rules on place.

Python objects are created to mimic ruleset objects (security zones, user groups, groups, etc.) and allows easy interaction with them.  For now read-only but should be easy make them writeable if you want.  Please dont expose this service without extra checks, designed to run in out-of-band network.

Requires two files on same directory to keys (check CPRulesWeb.py).
- .webkey.txt  -> key to access the builtin webserver and get the info
- .cpkey.txt   -> key to access the checkpoint management server


Example of API native CP rulebase query:
```json
{
    "uid": "e5b817c0-4ee7-4bcf-af11-0a1ef21cc66f",
    "name": "inside_access_in_opt",
    "rulebase": [
        {
            "uid": "7xxb-d287-4cbd-a68c-0ecabc9384cc",
            "name": "Allows IMAP Servers ",
            "type": "access-rule",
            "domain": {
                "uid": "4xx21a0-3720-11e3-aa6e-0800200c9fde",
                "name": "SMC User",
                "domain-type": "domain"
            },
            "rule-number": 1,
            "track": {
                "type": "5xxx32-aa42-4615-90ed-f51a5928d41d",
                "per-session": false,
                "per-connection": true,
                "accounting": false,
                "enable-firewall-session": false,
                "alert": "none"
            },
            "source": [
                "82cxxf6-f711-467a-b98d-9e583b52d19a",
                "e2bxx8ac-5661-474c-b078-4b7473bf67a7"
            ],
            "source-negate": false,
            "destination": [
                "44xx91a2-8418-425d-95dd-f7b6812865af"
            ],
            "destination-negate": false,
            "service": [
                "dbxx9d06-04a0-46e5-86b1-e79b26ca9877",
                "1exxae67-83d5-4d49-96e8-57b83c68d85b"
            ],
            "service-negate": false,
            "vpn": [
                "97xxb369-9aea-11d5-bd16-0090272ccb30"
            ],
            "action": "6xx88338-8eec-4103-ad21-cd461ac2c472",
            "action-settings": {
                "enable-identity-captive-portal": false
            },
            "content": [
                "97xxb369-9aea-11d5-bd16-0090272ccb30"
            ],
            "content-negate": false,
            "content-direction": "any",
            "time": [
                "97xxb369-9aea-11d5-bd16-0090272ccb30"
            ],
            "custom-fields": {
                "field-1": "",
                "field-2": "",
                "field-3": ""
            },
            "meta-info": {
                "lock": "unlocked",
                "validation-state": "ok",
                "last-modify-time": {
                    "posix": 1545801822256,
                    "iso-8601": "2022-02-25T12:10-0300"
                },
                "last-modifier": "roberto",
                "creation-time": {
                    "posix": 1543198155476,
                    "iso-8601": "2020-11-25T23:09-0300"
                },
                "creator": "WEB_API"
            },
            "comments": "",
            "enabled": true,
            "install-on": [
                "6cxx8338-8eec-4103-ad21-cd461ac2c476"
            ]
        },
```        


        
Example of API CPAux rulebase query:
GET http://127.0.0.1:5000/?k=xxxxxthujIgLqyFwt6w/w==

```json
{
    "rulebases": [
        {
            "uid": "e5b817c0-4ee7-4bcf-af11-0a1ef21cc66f",
            "name": "inside_access_in_opt",
            "rules": {
                "xxxx38bb-d287-4cbd-a68c-0ecabc9384cc": {
                    "uid": "xxxx38bb-d287-4cbd-a68c-0ecabc9384cc",
                    "name": "Allows IMAP Serverss",
                    "number": 1,
                    "sources": {
                        "xxxx6f6-f711-467a-b98d-9e583b52d19a": {
                            "uid": "xxxx56f6-f711-467a-b98d-9e583b52d19a",
                            "name": "grp_imap_externo",
                            "content": {
                                "xxxx2a8-aa11-408b-9c57-2a255a323561": {
                                    "uid": "xxxxa8-aa11-408b-9c57-2a255a323561",
                                    "name": "host_xxxxxd001",
                                    "ipv4_addr": "10.0.0.68",
                                    "ipv6_addr": null
                                },
                                "xxxxb12-5b12-4f61-bb66-5e85635903ff": {
                                    "uid": "xxxx6b12-5b12-4f61-bb66-5e85635903ff",
                                    "name": "hostxxxx03",
                                    "ipv4_addr": "10.0.0.54",
                                    "ipv6_addr": null
                                },
                                "xxxxe37-36e5-43b0-b878-bdb4fd8802cf": {
                                    "uid": "xxxx8e37-36e5-43b0-b878-bdb4fd8802cf",
                                    "name": "host_thiago",
                                    "ipv4_addr": "10.0.0.76",
                                    "ipv6_addr": null
                                },
                                "xxxx7c67-7bb0-4d13-bb61-d3ab110dac51": {
                                    "uid": "e4877c67-7bb0-4d13-bb61-d3ab110dac51",
                                    "name": ".T444.mydomain.local"
                                },
                                "xxxxaa00-5168-4cc1-b3ad-cc8be2cc32ec": {
                                    "uid": "xxxxa00-5168-4cc1-b3ad-cc8be2cc32ec",
                                    "name": "host_xxxx102",
                                    "ipv4_addr": "10.0.0.132",
                                    "ipv6_addr": null
                                }
                            }
                        },
                        xxxx8ac-5661-474c-b078-4b7473bf67a7": {
                            "uid": "xxxx78ac-5661-474c-b078-4b7473bf67a7",
                            "name": "host_xxxx101",
                            "ipv4_addr": "10.0.0.143",
                            "ipv6_addr": null
                        }
                    },
                    "sources_negate": false,
                    "destinations": {
                        "xxxx91a2-8418-425d-95dd-f7b6812865af": {
                            "uid": "xxxx91a2-8418-425d-95dd-f7b6812865af",
                            "name": ".imap.gmail.com"
                        }
                    },
                    "destinations_negate": false,
                    "services": {
                        "xxxxd06-04a0-46e5-86b1-e79b26ca9877": {
                            "uid": "xxxx9d06-04a0-46e5-86b1-e79b26ca9877",
                            "name": "UDP_993",
                            "type": "service-udp",
                            "port": "993"
                        },
                        "xxxxe67-83d5-4d49-96e8-57b83c68d85b": {
                            "uid": "xxxxe67-83d5-4d49-96e8-57b83c68d85b",
                            "name": "IMAP-SSL",
                            "type": "service-tcp",
                            "port": "993"
                        }
                    },
                    "last_modifier": "roberto",
                    "last_modify": "2022-02-25T12:10-0300",
                    "action": "",
                    "enabled": true,
                    "additional_info": "",
                    "ticket_number": "",
                    "ticket_requester": ""
                },
```
        
        
        
