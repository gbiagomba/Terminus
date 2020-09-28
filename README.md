# Terminus
This script was named after the roman god who protected boundary markers. The script checks a file with URLs to see if they can be reached via a curl command. The objective is to test to see if certain/any paths to a web server that requires authentication could be reached from a user who is not authenticated.

## Pre-requisite
I built this under the assumption that you ran an authenticated spider scan/crawl of the target web application or site using something like burp, acunetix or your web browser (see developer features of your browser). If you did not do that, I recommend doing so, or at least run dirbuster instead.

## Usage
```
terminus.sh urls.txt
```
