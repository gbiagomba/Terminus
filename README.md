# Terminus
This script checks a file with URLs to see if they can be reached via a curl command. The objective is to test to see if paths to a web server that requires authentication could be reached from a user who is not authenticated.

## Pre-requisite
I built this under the assumption that you ran performed a spider scan of a web application or site using something like burp, acunetix or your web browser (see developer feature of your browser). You can then copy those links, put them in a text file and point the script at it.
