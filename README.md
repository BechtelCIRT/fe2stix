# fe2stix
Simple API that digests FireEye notification (json) and generates a STIX XML document.

## Installation
### Prereqs
Install Python STIX to your system.
```
$ pip install stix
```
You can optionally install different versions of stix, see https://pypi.python.org/pypi/stix.
```
$ pip install stix-1.x.x.x
```

## Install
```
$ git clone https://github.com/BechtelCIRT/fe2stix
$ cd fe2stix
$ virtualenv ./
$ ./bin/pip install flask
```

## Configuration
Set the following constraints in the config.py file:
```
SAVE_DIRECTORY = "/tmp"
PRODUCER_NAME = "YOUR COMPANY"
PRODUCER_URL = "http://www.yourcompany.com"
```

## Test it out!
### Run the application
```
$ python app.py
```

### Post data with cURL
```
$ curl -H "Content-Type: application/json" -X POST -d '{JSON OBJECT}' http://youserver.com:5000/api/v1/fe
```

You should receive the following response:
```
{
  "Success": "STIX document succesfully generated,"
}
```
By default, inidcators will go to the /tmp directory.

### Configure FireEye Notification
1. Create HTTP Event
2. Add HTTP Server
3. Name it 'fe2stix'
4. Set the server URL as 'http://youserver.com:5000/api/v1/fe'
5. Notify for all events and deliver per event
6. Leave it as the generic provider
7. Select 'JSON Normal' for the message format
8. Submit a malicious sample, and watch the magic happen

### TODO
* Parse out additional indicators
* Provide Apache/WSGI daemon configuration
* Expand API to allow misc. POSTs of data and parse indicators

### License

Copyright (c) 2015 Andrew J Hill

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
