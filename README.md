# Defender-Asr-Blocked-Event-Sensor
# Microsoft Defender ASR Log Parser + Endpoint Managment Tool Sensor Integration

PowerShell sensor that parses Microsoft Defender for Endpoint **Attack Surface Reduction (ASR)** logs to gain early-stage visibility into threat behavior, blocked exploits, and system actions for faster incident response and enhanced endpoint protection. — ideal for endpoint visibility and enterprise reporting.

---

## Key Features

- Extracts the most recent ASR event (IDs `1121`/`1122`) from Defender logs
- Maps GUIDs to Microsoft Defender ASR rule names (e.g., “Block credential stealing from lsass.exe”)
- Outputs hostname, timestamp, rule name, rule ID, and short description
- Converts raw logs into actionable insights for security analysts
- Can act as a sensor for Tanium — feed results into dashboards and reports

---

## Why This Matters

ASR rules provide early warning signs of malicious behavior, including:

- Obfuscated scripts
- Office macro abuse
- Credential theft
- Unauthorized child processes

However, ASR logs are difficult to interpret natively. This script closes the visibility gap by:

- Automatically decoding rule GUIDs
- Providing readable threat context
- Delivering machine-level visibility to SOC, IR, and Threat Intel teams

---

## Example Output
LAPTOP-ACME|d4f940ab-401b-4efc-aadc-ad5f3c50688a|Block Office apps from creating child processes|Microsoft Defender blocked an app|2025-06-20T14:36:45.123Z

---

## Tanium Integration (Sensor Mode)

This script can be deployed as a custom sensor for endpoint management tools like Tanium to extend visibility across endpoints:

- Return ASR rule names and context to the endpoint management tool
- Feed data into dashboards for rule coverage tracking
- Enable reporting on ASR enforcement success/failures

---

## Disclaimer
The scripts included in this repository are provided as-is, with no warranties. Always test scripts in a safe and recoverable environment before deploying them in production.

Contributions, issues, and feature requests are welcome
Feel free to check the issues page.

---

## License
This project is MIT licensed.

