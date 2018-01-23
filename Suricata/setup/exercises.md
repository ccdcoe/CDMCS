# Exercises

 * Build your own suricata
   * set a custom installation root of your own choosing
     * configuration directory should be placed under /etc/suricata
   * it must support the following features:
     * EVE log in JSON format
     * redis output
     * suricatasc
     * [reading multiple pcap files from directory](http://suricata.readthedocs.io/en/latest/command-line-options.html#cmdoption-r)
     * NFS logging and output

## testing and hints

 * https://wiki.wireshark.org/SampleCaptures#NFS_Protocol_Family
 * https://www.malware-traffic-analysis.net/2018/index.html
 * ```curl testmyids.com```
 * https://github.com/OISF/suricata/blob/d05355db3d6e2752ae0582a7ea8c1a0f08bde91c/src/output-json-alert.c
