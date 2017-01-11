# packetmailwatcher
This package can read Packetmail P++ output at regular intervals and send you a notification on anything that has changed.

## Usage
```
      ./watcher.py <conffile> <CIDR> <sendtoemailaddress>
        conffile - Configuration file 
        CIDR - CIDR you are wanting to scan
        sendtoemailadress - email address for notifications of threat data changes.
        
      Example:
      ./watcher.py default.cnf 10.0.0.0/24 email@example.com
```
