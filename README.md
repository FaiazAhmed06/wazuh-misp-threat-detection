# Wazuh + MISP Integration Project  
Modified and documented by Faiaz Ahmed

In this project, I integrated Wazuh (open-source SIEM) with MISP (Malware Information Sharing Platform) to automate threat detection and intelligence correlation. The goal is to enrich Wazuh alerts with IOCs (Indicators of Compromise) from MISP and enable **active-response** actions for security events.  


---

## Features
- Automated threat intelligence integration with MISP  
- Custom rules and event correlation  
- Active response (block malicious IPs, brute force attempts, etc.)  
- Flexible architecture for extending dashboards, rules, and integrations  

---

## Architecture


| Event Type              | Metadata (Win / Linux)                | Purpose                                                       |
|--------------------------|---------------------------------------|---------------------------------------------------------------|
| Sysmon event 1          | `win.eventdata.hashes`                | Detect suspicious process image file hash                     |
| Sysmon event 3          | `destinationIp`                       | Detect malicious destination IPs (if global IPv4)             |
| Sysmon event 6          | `win.eventdata.hashes`                | Detect malicious loaded driver file hash                      |
| Sysmon event 7          | `win.eventdata.hashes`                | Detect suspicious DLL loads                                   |
| Sysmon event 15         | `win.eventdata.hashes`                | Detect malicious downloaded file hash                         |
| Sysmon event 22         | `win.eventdata.queryName`             | Detect DNS queries against malicious domains                  |
| Syscheck (Files)        | `syscheck.sha256_after`               | Detect file modifications and check against IoCs              |

---

## Custom Integration  

- Add Repository  
Copy the integration scripts into the Wazuh directory:  
```
cp custom-misp custom-misp.py /var/ossec/integrations/
```

- Fix Permissions
```
chown root:wazuh /var/ossec/integrations/custom-misp*
chmod 750 /var/ossec/integrations/custom-misp*
```

- Add integration to `/var/ossec/etc/ossec.conf`
```xml
<integration>
  <name>custom-misp</name>
  <group>Integration,misp,misp_alert,Network,Malware,sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck,recon,attack,web_scan,authenticat</group>
  <alert_format>json</alert_format>
</integration>
```

- Edit `custom-misp.py`
Update configuration:
```python
misp_base_url = "your-misp-url"
misp_api_auth_key = "your-misp-auth-key"
```

---

## Custom Rule  

Create `custom-rule.xml` inside `/var/ossec/etc/rules/`.  
Wazuh automatically loads any `.xml` rule file from that directory.

Example:
```xml
<group name="linux, webshell, windows,">
  <rule id="100503" level="13">
    <mitre>
      <id>T1105</id>
      <id>T1505.003</id>
    </mitre>
  </rule>
</group>
```

- Enable Debugging  
Edit `/var/ossec/etc/internal-options.conf`:  
```
integrator.debug=2
```

---

## Testing  

1. Creating test file in agent
```bash
echo "file_custom" > file01.txt
```

2. Generating hash
```bash
md5sum file01.txt
```
Add this hash as a custom IOC in MISP.

3. Creating another file with same contents
```bash
echo "file_custom" > file02.txt
```
If integration works, Wazuh will match the IOC against MISP.

4. Troubleshoot
```bash
tail -f /var/ossec/logs/ossec.log
tail -f /var/ossec/logs/integrations.log
```

---

## Active Response  

Configure `/var/ossec/etc/ossec.conf` to block brute-force attempts automatically:  

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100622,5705,5712,120100,5763</rules_id>
  <timeout>864001</timeout>
</active-response>
```

This blocks malicious IPs if specific rule IDs are triggered.

---

## Improvements  

- Build custom dashboards in Wazuh for visualization.  
- Add more rules and active-responses.  
- Extend integration with other platforms/tools.  

---

## Conclusion  
This project shows how I, built a working integration of Wazuh + MISP to automate threat intelligence correlation and response.  
It demonstrates the design SIEM integrations, write custom Python connectors, and apply SOC use cases with MITRE ATT&CK mapping.  

Next steps: scaling integrations, more active responses, and dashboard improvements.  
