"""
Main runner for Palo Alto toolkit to update Security Firewall Rules.
"""

import sys
import json
import requests
import xmltodict


from more_itertools import chunked
from requests.exceptions import ConnectionError


requests.packages.urllib3.disable_warnings()


# Global
PALO_IP = sys.argv[1]
PALO_USER = sys.argv[2]
PALO_PASSWORD = sys.argv[3]
DEVICE_GROUPS = sys.argv[4]


class RestAPI:
    def __init__(self, palo_host, username, password, group_name):
        self.palo_host = palo_host
        self.username = username
        self.password = password
        self.headers = {"X-PAN-KEY": ""}
        self.group_name = group_name
        self.pre_rules = {}
        self.post_rules = {}
        self.login()

    def login(self):
        base_url = f"https://{self.palo_host}"
        login_url = base_url + "/api/?type=keygen"
        params = {"user": self.username, "password": self.password}
        login_response = requests.get(login_url, params=params, verify=False)
        if login_response.status_code == 200:
            self.headers["X-PAN-KEY"] = xmltodict.parse(login_response.text)["response"]["result"]["key"]
        else:
            print("Unable to login to Palo Alto, Exiting...")
            sys.exit(-1)

    def fetch_pre_rules(self):
        params = {"location": "device-group", "device-group": self.group_name}
        get_response = requests.get(
            f"https://{self.palo_host}/restapi/9.0/Policies/SecurityPreRules",
            params=params,
            headers=self.headers,
            verify=False,
        )
        if get_response.status_code == 200:
            if json.loads(get_response.text)["@status"] == "success":
                self.pre_rules = json.loads(get_response.text)["result"]["entry"]

    def fetch_post_rules(self):
        params = {"location": "device-group", "device-group": self.group_name}
        get_response = requests.get(
            f"https://{self.palo_host}/restapi/9.0/Policies/SecurityPostRules",
            params=params,
            headers=self.headers,
            verify=False,
        )
        if get_response.status_code == 200:
            if json.loads(get_response.text)["@status"] == "success":
                self.post_rules = json.loads(get_response.text)["result"]["entry"]

    def update_pre_rules(self):
        for chunk_rules in chunked(self.pre_rules, 1000):
            commit = []
            for i in chunk_rules:
                params = {"location": "device-group", "device-group": self.group_name, "name": i["@name"]}
                if i["log-start"] == "yes":
                    i["log-start"] = "no"
                    _headers = {"X-PAN-KEY": self.headers["X-PAN-KEY"], "Content-Type": "application/json"}
                    put_response = requests.put(
                        f"https://{self.palo_host}/restapi/9.0/Policies/SecurityPreRules",
                        params=params,
                        headers=_headers,
                        data=json.dumps({"entry": i}),
                        verify=False,
                    )
                    if put_response.status_code == 200:
                        if json.loads(put_response.text)["@status"] == "success":
                            commit.append(True)
                        else:
                            commit.append(False)
                            print(f"Skipping: {i['@name']} - {i['@status']}")
                    else:
                        commit.append(False)
                        print(f"Error, Status Code: {put_response.status_code}")
                        print(put_response.reason)
            if all(commit):
                if self.commit(len(commit), "Pre"):
                    self.commit_all(len(commit), "Pre")

    def update_post_rules(self):
        for chunk_rules in chunked(self.post_rules, 1000):
            commit = []
            for i in chunk_rules:
                params = {"location": "device-group", "device-group": self.group_name, "name": i["@name"]}
                if i["log-start"] == "yes":
                    i["log-start"] = "no"
                    _headers = {"X-PAN-KEY": self.headers["X-PAN-KEY"], "Content-Type": "application/json"}
                    put_response = requests.put(
                        f"https://{self.palo_host}/restapi/9.0/Policies/SecurityPostRules",
                        params=params,
                        headers=_headers,
                        data=json.dumps({"entry": i}),
                        verify=False,
                    )
                    if put_response.status_code == 200:
                        if json.loads(put_response.text)["@status"] == "success":
                            commit.append(True)
                        else:
                            commit.append(False)
                            print(f"Skipping: {i['@name']} - {i['@status']}")
                    else:
                        commit.append(False)
                        print(f"Error, Status Code: {put_response.status_code}")
                        print(put_response.reason)
            if all(commit):
                if self.commit(len(commit), "Post"):
                    self.commit_all(len(commit), "Post")

    def commit(self, num_rules, rules_type):
        params = {"key": self.headers["X-PAN-KEY"], "type": "commit", "cmd": "<commit></commit>"}
        post_response = requests.post(
            f"https://{self.palo_host}/api",
            params=params,
            verify=False,
        )
        if post_response.status_code == 200:
            response = xmltodict.parse(post_response.text)["response"]
            if response["@status"] == "success":
                print(f"Successfully committed {num_rules} {rules_type} Firewall Rules to Panorama")
                return True
            else:
                print(f"Unable to commit this batch of {num_rules} {rules_type} Firewall Rules to Panorama")
                return False
        else:
            print(f"Unable to commit this batch of {num_rules} {rules_type} Firewall Rules to Panorama")
            return False

    def commit_all(self, num_rules, rules_type):
        params = {
            "key": self.headers["X-PAN-KEY"],
            "type": "commit",
            "action": "all",
            "cmd": f"<commit-all><shared-policy><device-group><entry name='{self.group_name}'/></device-group></shared-policy></commit-all>",
        }
        post_response = requests.post(
            f"https://{self.palo_host}/api",
            params=params,
            verify=False,
        )
        if post_response.status_code == 200:
            response = xmltodict.parse(post_response.text)["response"]
            if response["@status"] == "success":
                print(
                    f"Successfully committed {num_rules} {rules_type} Firewall Rules to all devices of group {self.group_name}"
                )
            else:
                print(
                    f"Unable to commit this batch of {num_rules} {rules_type} Firewall Rules to all devices of group {self.group_name}"
                )
        else:
            print(
                f"Unable to commit this batch of {num_rules} {rules_type} Firewall Rules to all devices of group {self.group_name}"
            )


def rest_setup(palo_host, device_group):
    try:
        palo_obj = RestAPI(palo_host, PALO_USER, PALO_PASSWORD, device_group)
        return palo_obj
    except ConnectionError:
        print(f"Unable to login to Palo Alto {palo_host}\n")
        sys.exit(-1)


def main():
    with open(DEVICE_GROUPS, "r") as f:
        device_groups = filter(None, (i.strip() for i in f.readlines() if i))
    for group in device_groups:
        palo_obj = rest_setup(PALO_IP, group)
        palo_obj.fetch_pre_rules()
        palo_obj.update_pre_rules()
        palo_obj.fetch_post_rules()
        palo_obj.update_post_rules()
        del palo_obj


if __name__ == "__main__":
    main()
