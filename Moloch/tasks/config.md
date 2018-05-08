# Basic configuration tasks

  * Change the default elasticsearch index period to weekly
  * Reduce the TCP session inactivity and total timeout values two-fold (50%)
  * Configure automatic deletion of PCAPs when there is less than 10% free space on the disk
  * Set the maximum PCAP file size to 10GB
  * Apply a BPF filter that would exclude default Moloch and elasticsearch ports from analysis
  * Replace libpcap with tpacketv3 with 3 packet threads and 5 workers

## Challenge

  * Create a multiple node capture system where two capture processes are monitoring different interfaces while both nodes have distinct node names

