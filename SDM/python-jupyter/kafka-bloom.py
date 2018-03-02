import json
import ipdb
from kafka import KafkaConsumer
import mmh3 as murmur

class bc:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'


# ==== BLOOM FILTER functions ==========

# Add True's to vector
def add(vector, pos):
    for p in pos:
        vector[p] = True
    return vector

# Check if item contain in vector
def check(vector, hashh):
    for p in hashh:
        if vector[p] is False:
            return False
    return True

# Hash the item
def hashing(item):
    h1 = murmur.hash64(item)
    hashes = []
    for i in range(1, k+1):
        uniq = ( h1[0] + i * h1[1]) % m
        hashes.append(uniq)
    return hashes


# ====== Variables ======
m = 100
k = 5
topic = "cee"
server = "IP:9093"

# Initialize vector vith False
bitvector = [ False for i in range(m) ]


# READ KAFKA

consumer = KafkaConsumer(topic, group_id=None, bootstrap_servers=server, auto_offset_reset='earliest')

logs = 300000
hosts = {}
i = 0
for msg in consumer:
	
    asd = json.loads(msg.value)
    hostn=asd["Hostname"].encode('utf-8')
    event = asd["EventType"].encode('utf-8')
    
    if hostn in hosts:
        hosts[hostn]["count"] += 1
    else:
        hosts[hostn] = {}
        hosts[hostn]["count"] = 1

    try:
        if hosts[hostn][event]:
            hosts[hostn][event] = hosts[hostn][event] + 1
    except:
        hosts[hostn][event] = 1

    if event in ["WARNING", "ERROR"]:

        # BLOOM FILTERING 
        

        try:
            stri =  "\nEventTime:\t{}\nHostname:\t{}\nProgramm:\t{}\nMessage:\t{}\n".format(asd["EventType"], asd["Hostname"], asd["program"], asd["Message"])
            #print stri

            item_hash =  hashing(stri)
            check_res = check(bitvector, item_hash)
            if check_res is False:
                print stri
                bitvector = add(bitvector, item_hash)
            else:
                print("BLOO FILTER")
    

        except Exception as inst:
            print asd
            print inst
    i += 1
     
    if i == logs:
       break
# output

print("results")
print "logs: {}".format(logs)

for aaa in hosts:
    count = hosts[aaa]["count"]
    del hosts[aaa]["count"]
    for bbb in hosts[aaa]:
        
        # Let's colorize
        if bbb in ["WARNING", "AUDIT_FAILURE"]:
            hosts[aaa]["{}{}{}".format(bc.WARNING, bbb, bc.END)] = hosts[aaa].pop(bbb)
        if bbb == "INFO":
            hosts[aaa]["{}{}{}".format(bc.OKBLUE, bbb, bc.END)] = hosts[aaa].pop(bbb)
        if bbb in ["INFOTMATION", "AUDIT_SUCCESS"]:
            hosts[aaa]["{}{}{}".format(bc.OKGREEN, bbb, bc.END)] = hosts[aaa].pop(bbb)
        if bbb in ["ERROR"]:
            hosts[aaa]["{}{}{}".format(bc.FAIL, bbb, bc.END)] = hosts[aaa].pop(bbb)

    # Prit it out
    print "{} ({})".format(aaa, count)
    for bbb in hosts[aaa]:
        print "\t{}: {}".format(bbb, hosts[aaa][bbb])

