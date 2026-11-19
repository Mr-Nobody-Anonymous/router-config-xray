# router-config-xray report

- Generated: 2026-11-19T15:55:47Z UTC
- Mode: read-only (no login, no state changes, no persistence/backdoor, no firmware flashing)

## Target: file:///home/anonymous/router-config-xray/samples/decoy_config.xml

**Summary:** Offline analysis of provided config file (for authorized review).

**Access condition:** Offline file analysis (no network request).

### Device info
```json
{
  "ManufacturerOUI": "001122",
  "ProductClass": "EXAMPLE-ROUTER-X1",
  "SerialNumber": "EXAMPLE123456",
  "DeviceSerialNumber": "EXAMPLE123456",
  "HardwareVersion": "V1.0",
  "SoftwareVersion": "V2.0.0",
  "X_Customer_MACAddress": "00:11:22:33:44:55",
  "TrueVendorID": "EXAMPLEVENDOR",
  "AccessType": "Gpon",
  "Product_ID": "EXAMPLE-ROUTER-X1"
}
```

### Admin/web account
```json
{
  "username": "admin",
  "password": {
    "raw": "ExampleAdminPass!",
    "recovered": "ExampleAdminPass!"
  }
}
```

### User GUI account
```json
{
  "username": "user",
  "password": {
    "raw": "ExampleUserPass!",
    "recovered": "ExampleUserPass!"
  }
}
```

### Service accounts
```json
{
  "FtpUserName": "ftpuser",
  "FtpPassword": {
    "raw": "ExampleFtpPass!",
    "recovered": "ExampleFtpPass!"
  }
}
```

### Wi-Fi
```json
[
  {
    "SSID": "ExampleWiFi",
    "Enable": "1",
    "BeaconType": "11i",
    "WPAAuthenticationMode": "PSKAuthentication",
    "IEEE11iEncryptionModes": "AESEncryption",
    "WlKey": {
      "raw": "ExampleWifiKey123",
      "recovered": "ExampleWifiKey123"
    },
    "PreSharedKeys": [
      {
        "raw": "\n          <PreSharedKey>ExampleWifiKey123",
        "recovered": "\n          <PreSharedKey>ExampleWifiKey123"
      }
    ]
  },
  {
    "SSID": "GuestNetwork",
    "Enable": "0"
  }
]
```

### TR-069/ACS/CWMP
```json
{
  "URL": "https://acs.example.invalid:7547/",
  "Username": "acs_user",
  "Password": {
    "raw": "acs_example_pass",
    "recovered": "acs_example_pass"
  },
  "PeriodicInformEnable": "1",
  "PeriodicInformInterval": "300",
  "ConnectionRequestUsername": "cr_user",
  "ConnectionRequestPassword": {
    "raw": "cr_example_pass",
    "recovered": "cr_example_pass"
  },
  "X_Customer_EnableCWMP": "1",
  "X_Customer_ConnectionRequestPort": "7547",
  "X_Customer_EnableCWMPWanAcl": "0",
  "X_Customer_ACL_IpAndMask": ""
}
```

### WAN
```json
[
  {
    "type": "WANPPPConnection",
    "Username": "pppoe_user@example.invalid",
    "Password": {
      "raw": "pppoe_example_pass",
      "recovered": "pppoe_example_pass"
    },
    "ExternalIPAddress": "203.0.113.10",
    "DefaultGateway": "203.0.113.1",
    "DNSServers": "198.51.100.53,198.51.100.54",
    "MACAddress": "00:11:22:33:44:55",
    "X_Customer_ServiceList": "INTERNET",
    "Name": "INTERNET_EXAMPLE",
    "Enable": "1",
    "ConnectionType": "IP_Routed",
    "NATEnabled": "1",
    "AddressingType": "PPPoE"
  }
]
```

### LAN
```json
[
  {
    "DHCPServerEnable": "1",
    "MinAddress": "192.168.0.100",
    "MaxAddress": "192.168.0.200",
    "SubnetMask": "255.255.255.0",
    "LAN_IP": "192.168.0.1"
  }
]
```

### Impact assessment (informational)
```json
{
  "impact_assessment": "high",
  "potential_impacts": [
    "Administrative account material exposed — may enable full device management access if reused/valid.",
    "Wireless network credentials/keys exposed — may enable unauthorized network access and traffic visibility.",
    "Remote management (TR-069/ACS/CWMP) details exposed — may increase risk of remote provisioning abuse depending on reachability and controls.",
    "WAN/PPPoE/service details exposed — may aid service abuse, impersonation, or targeted attacks.",
    "Additional user/service account material exposed."
  ],
  "factors": [
    "Reachability matters: LAN/Wi-Fi exposure differs from internet/WAN exposure.",
    "No authentication required for the exposed endpoint increases risk when reachable.",
    "Router/gateway compromise can have downstream impact on connected devices and traffic.",
    "Actual impact depends on credential validity, service exposure, and mitigations — assess in your environment."
  ],
  "note": "This tool reports observed exposure and indicators; it does not assign a definitive severity/CVSS score."
}
```
