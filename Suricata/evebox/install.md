# EveBox install on Debian | Ubuntu

* https://github.com/jasonish/evebox#installation
* https://codemonkey.net/evebox/#Downloads


[[ -f $EVEBOX ]] ||wget  -q -4 https://bintray.com/jasonish/evebox-development-debian/download_file?file_path=$EVEBOX -O $EVEBOX
dpkg -i $EVEBOX > /dev/null 2>&1
echo 'ELASTICSEARCH_INDEX="evebox"' >> /etc/default/evebox
