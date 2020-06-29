#!/bin/bash
#Author: Gilles Biagomba
#Program: terminus.sh
#Description: This script checks a file with URLs to see if they can be reached via a curl command.\n
#	      The objective is to test to see if paths to a web server that requires authentication \n
#	      Could be reached from a user who is not authenticated\n
#	      reference: https://stackoverflow.com/questions/6136022/script-to-get-the-http-status-code-of-a-list-of-urls


# for debugging purposes
# set -eux
trap "echo Booh!" SIGINT SIGTERM

# Checking if the user is root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# declaring variable
pth=$(pwd)
TodaysDAY=$(date +%m-%d)
TodaysYEAR=$(date +%Y)
wrkpth="$pth/$TodaysYEAR/$TodaysDAY"

# Capturing file from user
links=$1
if [ ! -r $links ]; then
    echo file does not exist, please enter a valid filename
    echo usage 'terminus.sh links.txt'
    exit
fi

echo What is the project name?
read Prj_name

# Stting up workspace
mkdir -p $wrkpth/OUTPUT $wrkpth/PARSED $wrkpth/EVIDENCE $wrkpth/EyeWitness/ $wrkpth/Screenshots/

# Going through urls and trying to download them
for URL in $(cat $links); do
	for webservmethod in ACL BASELINE-CONTROL BCOPY BDELETE BMOVE BPROPFIND BPROPPATCH CHECKIN CHECKOUT CONNECT COPY DEBUG DELETE GET HEAD INDEX LABEL LOCK MERGE MKACTIVITY MKCOL MKWORKSPACE MOVE NOTIFY OPTIONS ORDERPATCH PATCH POLL POST PROPFIND PROPPATCH PUT REPORT RPC_IN_DATA RPC_OUT_DATA SEARCH SUBSCRIBE TRACE UNCHECKOUT UNLOCK UNSUBSCRIBE UPDATE VERSION-CONTROL X-MS-ENUMATTS; do
		curl -k -L -o /dev/null --silent -X $webservmethod --write-out "%{http_code} $URL\n" "$URL" -o $wrkpth/Screenshots/$URL-$webservmethod.png | tee -a $wrkpth/OUTPUT/HTTP-$webservmethod-output.txt &
	done
	while pgrep -x curl > /dev/null; do sleep 10; done
done

# Parsing the output from the previous step
for i in `ls $wrkpth/OUTPUT/`; do
	for j in 000 200 301 400 401 404 405 411 502; do
		cat $i | grep $j | sort | >> $wrkpth/PARSED/HTTP_Code_$j 
	done
done
cat $wrkpth/OUTPUT/HTTP_*_output.txt | sort | uniq > $wrkpth/OUTPUT/HTTP_Combined

# Fetching Successful downloadeds
eyewitness -f "$wrkpth/PARSED/HTTP_Code_200" --prepend-https --threads 25 --no-prompt --resolve -d $wrkpth/EyeWitness/

for URL in `cat $wrkpth/PARSED/HTTP_Code_200 | cut -d " " -f 2`;do
	wget -bpk $URL 2> /dev/null
	cutycapt --url=$URL --out=$wrkpth/Screenshots/$URL.jpg --insecure --max-wait=1000  2> /dev/null &
	while pgrep -x curl > /dev/null; do sleep 10; done
done

# Zipping up findings
cd $pth
zip -ru9 $pth/$prj_name-$TodaysYEAR.zip $pth/$TodaysYEAR

# Empty file cleanup
find $wrkpth -type d,f -empty | xargs rm -rf

# Uninitializing variables
unset pth
unset TodaysDAY
unset TodaysYEAR
unset URL
unset wrkpth
set -u
