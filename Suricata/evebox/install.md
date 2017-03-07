# EveBox install on Debian | Ubuntu


before install please see [installing elasticsearch](/common/elastic.install.md)

see:
* https://github.com/jasonish/evebox#installation
* https://codemonkey.net/evebox/#Downloads

```

EVEBOX="evebox_0.6.0dev~dev20170307033423_amd64.deb"

[[ -f $EVEBOX ]] ||wget  -q -4 https://bintray.com/jasonish/evebox-development-debian/download_file?file_path=$EVEBOX -O $EVEBOX

dpkg -i $EVEBOX

```

----

Next -> [Configuration](config.md)
