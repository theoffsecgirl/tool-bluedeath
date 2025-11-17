# BLUEDEATH

Bluetooth security auditing tool for BR/EDR devices.  
Includes scan utilities, connectivity checks, active device probing and controlled `l2ping` stress-testing.

## Features
- Scan for nearby Bluetooth devices  
- Detect active devices (l2ping response)  
- Check connectivity and basic status  
- Controlled stress-test with confirmation  
- Export scan results to file  
- Customizable interface (`hci0`, `hci1`, etc.)

## Requirements
- Linux  
- Bash  
- bluez (`hcitool`, `hciconfig`, `l2ping`)  
- Superuser privileges  
- Compatible Bluetooth adapter

## Installation
```bash
git clone https://github.com/theoffsecgirl/tool-bluedeath
cd tool-bluedeath
chmod +x bluedeath.sh
````

## Usage

Interactive mode:

```bash
sudo ./bluedeath.sh
```

Force interface:

```bash
sudo BT_INTERFACE=hci1 ./bluedeath.sh
```

## Ethical use

This tool must only be used in authorized environments.
Unauthorized use may be illegal.
