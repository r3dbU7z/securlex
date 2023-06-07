#!/bin/bash
# URLhaus CSV fields:
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
# Example SQL query:
#"SELECT url FROM \
#	(SELECT url,url_status,tags,reporter FROM \
#		${table_name} WHERE url_status='${_status}' \
#		AND tags REGEXP '${_tag}' \
#		AND reporter='${username}');
#
printf "\nSECURLEX - URLsecator\n Script for export online|offline hosts from URLhaus CSV file to IPs list(.txt).\n\n"
#Get options
while getopts "f:t:n:o:w:sch" opt
do
case $opt in
f) printf "Selected CSV database filename: $OPTARG\n"
	csv_file=$OPTARG
	;;
c) printf  "Check IPs online status - on.\n"
	scanflag="flagOn"
	;;
t) printf  "Selected tag: $OPTARG\n"
	_tag=$OPTARG
	;;
n) printf  "Selected URLhaus username: $OPTARG\n"
	username=$OPTARG
	;;
o)	printf "Selected output filename: $OPTARG\n"
	out_filename=$OPTARG
	;;
s)	printf "Selected URLs status: online\n"
	_status="online"
	;;
w)printf  "Selected cURL scan timeout: $OPTARG sec.\n"
	timeout=$OPTARG
	;;
h)	printf "Usage: $(basename $0) [-f<filename>][-t<tags>][-s][-c][-n<Username>][-w<4>][-o fileout.txt]\n"
	printf "	-f <filename> - CSV database filename\n"
	printf "	-t <tags> - set tags filter / default: 'mirai'\n"
	printf "	-s - set filter URLs status to 'online' (optional) / default: 'offline'\n"
	printf "	-c - check URLs status; Get HTTP response code (optional) / default: 'off'\n"
	printf "	-n <Username> - set URLhaus username filter (optional)\n"
	printf "	-w <4> - set cURL timout in sec.(optional) / default: '1' sec.\n"
	printf "	-o fileout.txt - set output filename (optional) / default 'offline_mirai_hosts.txt'\n"
	printf "	./securlex.sh -s -f urlhaus.cve -t mirai -n r3dbU7z\n"
	exit 0
	;;
*) printf  "No reasonable options found!\n"
;;
esac
done
#Database dump URLs on URLhaus site
#https://urlhaus.abuse.ch/downloads/csv_recent/
#https://urlhaus.abuse.ch/downloads/csv_online/
filename="urlhaus.csv"

_select_file(){
	prompt="Please select CSV file:"
	foptions=( $(find ./ -maxdepth 1 -type f -name "*.csv" -print0 | xargs -0) )
	PS3="$prompt "
	select opt in "${foptions[@]}" "Quit" ; do 
		if (( REPLY == 1 + ${#foptions[@]} )) ; then
			exit
		elif (( REPLY > 0 && REPLY <= ${#foptions[@]} )) ; then
			printf  "CSV file: $opt\n"
			filename=$opt
			break
		else
			printf "Invalid option. Try another one.\n"
		fi
	done    
ls -ld "$opt"
}

_get_csvdump(){
	printf "\nDownload ${_urldump} in file ${filename}\n"
	curl -o ${filename} ${_urldump}	
}

_menu(){
PS3="Please select source database dump:"
options=("Get recent dump" "Get online dump"  "Enter file" "Select file" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Get recent dump")
			printf "\nDownload database dump (CSV)\n\n"
            printf "URLhaus database dump (CSV) containing recent additions (URLs) only (past 30 days)\n"
			_urldump="https://urlhaus.abuse.ch/downloads/csv_recent/"
			filename="recent_${filename}"
			_get_csvdump
			break
            ;;
        "Get online dump")
			printf "\nDownload database dump (CSV)\n\n"
            printf "URLhaus database dump (CSV) containing only online (active) malware URLs:\n"
			_urldump="https://urlhaus.abuse.ch/downloads/csv_online/"
			filename="online_${filename}"
			_get_csvdump
			break
            ;;
        "Enter file")
            printf "\nEnter /path/to/filename:\n"
			printf "../\n"
			ls | grep .csv
			read filename
			filename=$(basename -- "$filename")
			break
            ;;
		"Select file")
			#Select file in cur. dir
			_select_file
			break
			;;
        "Quit")
            exit 0;
            ;;
        *) printf"invalid option $REPLY\n";;
    esac
done
}
_sqlExport(){
#Check exist CSV file 
if [ -z  ${csv_file+x} ]; then
	printf  "CSV file not found!\n"
	#Call menu script for select file
	_menu
	csv_file=${filename}
	#exit 0;
fi
local csv_filename=$(basename -- "$csv_file")
#Replace all hyphens in table name for sqlite3
local table_name=$(echo "${csv_filename%.*}" | sed 's/-/_/g')
#Set tagname
if [ -z  ${_tag+x} ]; then
	printf  "Selected Tag: 'mirai'\n"
	local _tag="mirai"
fi
#Set URL status
if [ -z  ${_status+x} ]; then
	printf  "Selected status: 'offline'\n"
	local _status="offline"
fi
#Set output filename
if [ -z  ${out_filename+x} ]; then
	printf "Selected output filename: '${_status}_${_tag}_hosts.txt'\n"
	local out_filename="${_status}_${_tag}_hosts.txt"
fi
#TODO REGEXP filter for multiple tags 
#Check username
if [ -z  ${username+x} ]; then
	#Export URLs with tag and status filters
	_sql_query="SELECT url FROM (SELECT url,url_status,tags FROM ${table_name} WHERE tags REGEXP '${_tag}' AND url_status='${_status}');"
else
	printf  "Selected URLhaus username: ${username}.\n"
	#Export URLs with tag, status and reporter filters
	_sql_query="SELECT url FROM (SELECT url,url_status,tags,reporter FROM ${table_name} WHERE reporter='${username}' AND tags REGEXP '${_tag}' AND url_status='${_status}');"
	out_filename=${_status}_${_tag}_hosts_by_${username}.txt;
fi
#Check dump header
fheader=$(head -n2 ${csv_filename} | grep -o "URLhaus Database Dump" )
if [[ "$fheader" == "URLhaus Database Dump" ]]; then
	#!Remove URLhaus banner - first 8 lines
	printf "Remove URLhaus banner from file ${csv_filename} .\n"
	#Without backups
	sed -i '1,8d' ${csv_filename}  # <-- EDIT THIS if necessary to save original file
fi
printf "Export URLs... to '${out_filename}'\n"
ips_filename=${out_filename};
#Import CSV to SQL dbase
./sqlite3 -csv << END_SQL | cut -d '/' -f 3 | cut -d ':' -f 1  | sort | uniq > ${out_filename}; #URLs to IPs list
#.headers on
.import ${csv_filename} ${table_name}
${_sql_query}
END_SQL
printf "Export done.\n"
}
#Call export
_sqlExport

printf "IPs list in - '${ips_filename}' file.\n"

_check_online_status(){
	#Read IPs list from file
	readarray _ip < $ips_filename
	#Get HTTP response status codes
	for ip in ${_ip[@]};do 
		if  [ -z ${timeout+x} ]; then
			local timeout=1
		fi	
		respcode=$(curl --max-time $timeout -Is http://$ip | head -n1 | awk '{print$2}')
		#printf "IP: $ip - HTTP - ${respcode}\n" | 2>&1 tee -a $(echo scanlog_$(date '+%Y-%m-%d').log)
		printf "IP: $ip - HTTP - ${respcode}\n"
	done
}
#Call scan func
if [[ -e "$ips_filename" && "$scanflag" == "flagOn" ]]; then
	printf "\nLet's check out IPs online status...\n\n"
	_check_online_status
fi

exit 0
