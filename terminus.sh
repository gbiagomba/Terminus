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

# declaring variable
current_time=$(date "+%Y.%m.%d-%H.%M.%S")
links=$1
prj_name=$2
pth=$(pwd)
wrkpth="$PWD/terminus"

if [ ! -r $links ]; then
    echo file does not exist, please enter a valid filename
    echo usage 'terminus.sh links.txt'
    exit
elif [ -z $prj_name ]; then
	echo What is the project name?
	read prj_name
fi

{
	# Stting up workspace
	for i in OUTPUT PARSED EVIDENCE EyeWitness Screenshots Aquatone Wget; do mkdir -p $wrkpth/$i; done

	# Going through urls and trying to download them
	echo "Going through urls and trying to download them"
	for URL in $(cat $links); do
		for webservmethod in ACL BASELINE-CONTROL BCOPY BDELETE BMOVE BPROPFIND BPROPPATCH CHECKIN CHECKOUT CONNECT COPY DEBUG DELETE GET HEAD INDEX LABEL LOCK MERGE MKACTIVITY MKCOL MKWORKSPACE MOVE NOTIFY OPTIONS ORDERPATCH PATCH POLL POST PROPFIND PROPPATCH PUT REPORT RPC_IN_DATA RPC_OUT_DATA SEARCH SUBSCRIBE TRACE UNCHECKOUT UNLOCK UNSUBSCRIBE UPDATE VERSION-CONTROL X-MS-ENUMATTS; do
			curl -kLs --max-time 3 -X $webservmethod --write-out "%{http_code} $URL\n"  -o /dev/null "$URL" | tee -a $wrkpth/OUTPUT/HTTP-$webservmethod-output.txt &
		done
		while pgrep -x curl > /dev/null; do sleep 10; done
	done

	# Parsing the output from the previous step
	echo "Parsing the output from the previous step"
	for i in `ls $wrkpth/OUTPUT/`; do
		cat $wrkpth/OUTPUT/$i | egrep -i "000|200|301|400|401|404|405|411|502" | grep -i http | cut -d " " -f 2 | sort -fu >> $wrkpth/PARSED/HTTP_Filtered_Responses.txt
	done
	cat $wrkpth/OUTPUT/HTTP-*-output.txt | sort -fu > $wrkpth/OUTPUT/HTTP_Combined.list

	# Fetching Successful downloads
	echo "Fetching Successful downloads"
	eyewitness -f "$wrkpth/PARSED/HTTP_Filtered_Responses.txt" --prepend-https --threads 25 --no-prompt --resolve -d $wrkpth/EyeWitness/
	cat $wrkpth/PARSED/HTTP_Filtered_Responses.txt | aquatone -threads 10 -out $wrkpth/Aquatone/

	cd $wrkpth/Wget/
	for URL in $(cat $wrkpth/PARSED/HTTP_Filtered_Responses.txt); do
		for webservmethod in ACL BASELINE-CONTROL BCOPY BDELETE BMOVE BPROPFIND BPROPPATCH CHECKIN CHECKOUT CONNECT COPY DEBUG DELETE GET HEAD INDEX LABEL LOCK MERGE MKACTIVITY MKCOL MKWORKSPACE MOVE NOTIFY OPTIONS ORDERPATCH PATCH POLL POST PROPFIND PROPPATCH PUT REPORT RPC_IN_DATA RPC_OUT_DATA SEARCH SUBSCRIBE TRACE UNCHECKOUT UNLOCK UNSUBSCRIBE UPDATE VERSION-CONTROL X-MS-ENUMATTS; do
			wget --method $webservmethod --append-output $wrkpth/Wget/wget.log -bpkq $URL 2> /dev/null &
		done
		while pgrep -x wget > /dev/null; do sleep 10; done
	done
	cd $OLDPWD

	# File cleanup & Zipping up findings
	echo "File Cleanup & Zipping up findings"
	for i in d f; do find $wrkpth -type $i -empty -delete; done
	mv $pth/wget-log* $wrkpth/Wget-logs/
	zip -ru9 $pth/$prj_name-terminus_output-$current_time.zip $wrkpth/
} 2> /dev/null | tee -a $pth/$prj_name-terminus_output-$current_time.txt

# Uninitializing variables
unset pth
unset URL
unset wrkpth
set -u