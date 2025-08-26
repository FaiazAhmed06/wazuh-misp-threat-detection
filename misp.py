#!/usr/bin/env python3
# Modified and maintained by Faiaz Ahmed
# MISP API Integration (Refactored v2)

import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import hashlib
import re

# (Optional) silence "InsecureRequestWarning" since we use verify=False below.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# Paths / socket used by Wazuh
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = f"{pwd}/queue/sockets/queue"

def send_event(msg, agent=None):
    """
    Send the integration result back to Wazuh via its UNIX datagram socket.
    """
    try:
        if not agent or agent.get("id") == "000":
            string = f'1:misp:{json.dumps(msg)}'
        else:
            string = '1:[{id}] ({name}) {ip}->misp:{payload}'.format(
                id=agent.get("id", "000"),
                name=agent.get("name", "unknown"),
                ip=agent.get("ip", "any"),
                payload=json.dumps(msg),
            )

        # DEBUG OUTPUT (printed to integrations.log when debug enabled)
        print(f"DEBUG_OUTPUT: {string}")

        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
    except Exception as e:
        # Last-resort logging to help diagnose socket issues
        try:
            print(f"DEBUG_OUTPUT: send_event_error={e}")
        except Exception:
            pass


# --- Read the incoming Wazuh alert (JSON) ---
with open(sys.argv[1]) as alert_file:
    alert = json.loads(alert_file.read())

alert_output = {}

# --- MISP configuration (fill these with your values) ---
misp_base_url = "your-misp-url"
misp_api_auth_key = "your-misp-auth-key"
misp_apicall_headers = {
    "Content-Type": "application/json",
    "Authorization": f"{misp_api_auth_key}",
    "Accept": "application/json",
}
HTTP_TIMEOUT = 10  # seconds

# Get MISP event details (for threat level and info)
def get_event_details(event_id):
    misp_event_url = f"{misp_base_url}/events/view/{event_id}"
    try:
        response = requests.get(
            misp_event_url,
            headers=misp_apicall_headers,
            verify=False,
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        event_data = response.json()
        if event_data and "Event" in event_data:
            return event_data["Event"]
    except requests.exceptions.RequestException:
        pass
    return None

# Search an attribute in MISP and emit an alert back to Wazuh
def misp_search_and_alert(search_value, alert_output, alert, extra_fields=None, file_path=None):
    misp_search_url = f"{misp_base_url}/attributes/restSearch/value:{search_value}"
    print(misp_search_url)

    try:
        misp_api_response = requests.get(
            misp_search_url,
            headers=misp_apicall_headers,
            verify=False,
            timeout=HTTP_TIMEOUT,
        )
        misp_api_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        alert_output["integration"] = "misp"
        alert_output["misp"] = {
            "error": f"Connection or API Error: {e}",
            "value": search_value,
        }
        send_event(alert_output, alert.get("agent"))
        return False

    response_json = misp_api_response.json()
    alert_output["integration"] = "misp"
    alert_output["misp"] = {}

    # If attribute(s) found
    if (
        response_json.get("response")
        and "Attribute" in response_json["response"]
        and response_json["response"]["Attribute"]
    ):
        attr = response_json["response"]["Attribute"][0]
        event_id = attr.get("event_id")

        alert_output["misp"]["found_attribute"] = "True"
        alert_output["misp"]["value"] = attr.get("value")
        alert_output["misp"]["category"] = attr.get("category")
        alert_output["misp"]["type"] = attr.get("type")
        alert_output["misp"]["event_id"] = event_id

        if file_path:
            alert_output["misp"]["file_path"] = file_path

        # convenience for IP-based AR, etc.
        if attr.get("type") in ["ip-src", "ip-dst"]:
            alert_output["srcip"] = attr.get("value")

        # Enrich with event threat level / info
        if event_id:
            event_details = get_event_details(event_id)
            if event_details:
                threat_level_id = int(event_details.get("threat_level_id", 4))
                threat_level_map = {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}
                alert_output["misp"]["threat_level"] = threat_level_map.get(threat_level_id, "Unknown")
                alert_output["misp"]["event_info"] = event_details.get("info", "N/A")

    # If attribute NOT found
    else:
        alert_output["misp"]["found_attribute"] = "False"
        alert_output["misp"]["value"] = search_value

    # Emit result back to Wazuh (always)
    send_event(alert_output, alert.get("agent"))
    return True


# --- Main rule logic mapping ---
regex_file_hash = re.compile(r"\w{64}")
event_source = alert["rule"]["groups"][0]
try:
    event_type = alert["rule"]["groups"][2]
except IndexError:
    decoder_name = alert["decoder"]["name"]

if event_source == "windows":
    # Windows Sysmon mappings
    hashes_path = [
        ("sysmon_event1", lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
        ("sysmon_event3", lambda: alert["data"]["win"]["eventdata"].get("destinationIp")),
        ("sysmon_event6", lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
        ("sysmon_event7", lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
        ("sysmon_event_15", lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
        ("sysmon_event_22", lambda: alert["data"]["win"]["eventdata"].get("queryName")),
        ("sysmon_event_23", lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
        ("sysmon_event_24", lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
        ("sysmon_event_25", lambda: regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)),
    ]
    for etype, getter in hashes_path:
        if event_type == etype:
            try:
                wazuh_event_param = getter()
            except Exception:
                sys.exit()
            # For event3, check if destination IP is public IPv4
            if etype == "sysmon_event3":
                is_ipv6 = alert["data"]["win"]["eventdata"].get("destinationIsIpv6")
                if is_ipv6 == "false" and wazuh_event_param and ipaddress.ip_address(wazuh_event_param).is_global:
                    misp_search_and_alert(wazuh_event_param, alert_output, alert)
                sys.exit()
            else:
                misp_search_and_alert(
                    wazuh_event_param,
                    alert_output,
                    alert,
                    extra_fields={"misp": {"source": {"description": alert["rule"].get("description", "")}}},
                )
            break
    else:
        sys.exit()

elif event_source == "linux":
    if event_type == "sysmon_event3" and alert["data"]["eventdata"].get("destinationIsIpv6") == "false":
        try:
            dst_ip = alert["data"]["eventdata"].get("DestinationIp")
            if ipaddress.ip_address(dst_ip).is_global:
                misp_search_and_alert(dst_ip, alert_output, alert)
            else:
                sys.exit()
        except Exception:
            sys.exit()
    elif event_type == "sysmon_event1" and alert["data"]["eventdata"].get("commandLineCommand") in ["nslookup", "ping"]:
        try:
            wazuh_event_param = alert["data"]["eventdata"].get("commandLineParameter")
            misp_search_and_alert(wazuh_event_param, alert_output, alert)
        except Exception:
            sys.exit()
    else:
        sys.exit()

elif event_source == "syscheck" and (decoder_name == "syscheck_new_entry" or decoder_name == "syscheck_integrity_changed"):
    md5_after = alert.get("syscheck", {}).get("md5_after")
    sha256_after = alert.get("syscheck", {}).get("sha256_after")
    file_path = alert.get("syscheck", {}).get("path")
    if md5_after:
        # skip empty file hash
        if md5_after == "d41d8cd98f00b204e9800998ecf8427e":
            sys.exit()
        misp_search_and_alert(md5_after, alert_output, alert, file_path=file_path)
    if sha256_after:
        misp_search_and_alert(sha256_after, alert_output, alert, file_path=file_path)

elif event_source == "ossec" and (event_type == "syscheck_entry_added" or event_type == "syscheck_entry_modified"):
    md5_after = alert.get("syscheck", {}).get("md5_after")
    file_path = alert.get("syscheck", {}).get("path")
    if md5_after:
        if md5_after == "d41d8cd98f00b204e9800998ecf8427e":
            sys.exit()
        misp_search_and_alert(md5_after, alert_output, alert, file_path=file_path)

elif event_source == "web" and (event_type == "web_scan" or event_type == "attack"):
    try:
        wazuh_event_param = alert["data"].get("srcip")
        found = misp_search_and_alert(
            wazuh_event_param, alert_output, alert, extra_fields={"srcip": wazuh_event_param}
        )
        if found:
            with open("/var/ossec/etc/lists/misp_ip_lists.txt", "a") as file:
                file.write(wazuh_event_param + "\n")
    except Exception:
        sys.exit()

elif event_source == "syslog" and event_type == "authentication_failed":
    try:
        wazuh_event_param = alert["data"].get("srcip")
        found = misp_search_and_alert(
            wazuh_event_param, alert_output, alert, extra_fields={"srcip": wazuh_event_param}
        )
        if found:
            with open("/var/ossec/etc/lists/misp_ip_lists.txt", "a") as file:
                file.write(wazuh_event_param + "\n")
    except Exception:
        sys.exit()
else:
    sys.exit()
