#!/bin/sh
# 
# Insert the API key in the wget command

rm -f online-valid.csv
wget -q http://data.phishtank.com/data/API_KEY/online-valid.csv.bz2
bunzip2 online-valid.csv.bz2
rm feed.txt
wget -q https://openphish.com/feed.txt

keywords=`cat keywords_alert.yaml | sed -e "s/'//g" -e "s/://g" -e "s/ //g" `
keywords="$keywords "
reported_phish="reported_phish.out"

gr1="cat online-valid.csv | grep "
gr2="cat feed.txt | grep "

for i in $keywords
do
  gr1="$gr1 -e $i "
  gr2="$gr2 -e $i "
done

phishtank=`eval ${gr1}` 
openphish=`eval ${gr2}` 

echo $phishtank > $reported_phish 
echo $openphish >> $reported_phish 
