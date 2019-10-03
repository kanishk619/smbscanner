# smbscanner
SMB Scanner made with Impacket to scan and find open shares across the network.

## Scan a single ip
```python
from core.scanner import SMBScanner
s = SMBScanner('', '', '')
s.scan('10.0.0.1')
```

## Scan a CIDR range
```python
s.scan('10.0.0.4/24')
```

## Scan custom range
```python
s.scan('10.0.0.1-10.0.2.255')
```

## Write results to a CSV file 
```python
from core.outputHandler import CsvHandler
from core.scanner import SMBScanner
import logging

csvHandler = CsvHandler()
smbscan_logger = logging.getLogger('smbscanner')
smbscan_logger.addHandler(csvHandler)

username = ''
password = ''
domain = ''

s = SMBScanner(username, password, domain, threads=256, thread_timeout=2)
s.scan('10.0.0.1/24')
```

## Ship output to an ElasticSearch Instance
```python
from core.outputHandler import ElasticHandler
from core.scanner import SMBScanner
import logging

smbscan_logger = logging.getLogger('smbscanner')
elastic = ElasticHandler('localhost', 9200)    # ship this to ElasticSearch instance
smbscan_logger.addHandler(elastic)

username = ''
password = ''
domain = ''

s = SMBScanner(username, password, domain, threads=256, thread_timeout=2)
s.scan('10.0.0.1/24')
```


## Ship output to an ElasticSearch Instance
```python
from core.outputHandler import ElasticHandler
from core.scanner import SMBScanner
import logging

smbscan_logger = logging.getLogger('smbscanner')
elastic = ElasticHandler('localhost', 9200)    # ship this to ElasticSearch instance
smbscan_logger.addHandler(elastic)

username = ''
password = ''
domain = ''

s = SMBScanner(username, password, domain, threads=256, thread_timeout=2)
s.scan('10.0.0.1/24')
```


## Handle output with some custom logic
```python
from logging import StreamHandler

class MyCustomHandler(StreamHandler):
    def __init__(self, stream=None):
        super(CsvHandler, self).__init__(stream=stream)

    def emit(self, record):
        smb_info = getattr(record, 'smb_info', None)
        if smb_info:
            # do something
            
smbscan_logger = logging.getLogger('smbscanner')
ch = MyCustomHandler()
smbscan_logger.addHandler(ch)
```
