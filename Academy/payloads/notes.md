## Disable AV windows

    PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true

## Creating a payload with MSvenom

check list of payloads

    msfvenom -l payloads