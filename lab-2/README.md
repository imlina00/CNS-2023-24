# ARP spoofing

## Recovered Challenge

username: mlinarevic_ivona
password: adtathente
access_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtbGluYXJldmljX2l2b25hIiwic2NvcGUiOiJhcnAiLCJleHAiOjE3MTEwMTUwMTl9.UBtd3HWPDOLCv4Jc1YW3EJfGF3ZnRyq3F4lzqOS0Ydg
cookie: stomasheprnofout

{antitirofo}
  
## IP header

Crypto oracle (IP):	10.0.15.1
Crypto oracle (MAC): 02:42:0a:00:0f:01

ARP client (IP): 10.0.15.39
ARP client (MAC): 02:42:0a:00:0f:27

Attacker (IP): 10.0.15.2
Attacker (MAC): 02:42:0a:00:0f:02

### IP header before attack

IP package: 02:42:0a:00:0f:27 | 02:42:0a:00:0f:01 | 10.0.15.39 | 10.0.15.1 | username&password

### IP header after the attack

IP package: 02:42:0a:00:0f:27 | 02:42:0a:00:0f:02 | 10.0.15.39 | 10.0.15.2 | username&password
