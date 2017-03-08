#!/bin/bash

STUDENTCOUNT=1

cd ../students/ || exit
read -p "Are you sure? " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # do it
    echo "($date) creating Vagrantfiles for $STUDENTCOUNT students"
    for studentno in $(seq 1 $STUDENTCOUNT)
    do
        [[ -d "./student-$studentno" ]] && exit
        echo "$(date) creating directory ./student-$studentno "
        mkdir ./student-$studentno || exit
        cat ../templates/student78/Vagrantfile | sed "s/studentNumber = ../studentNumber = ${studentno}/" > ./student-$studentno/Vagrantfile
        cd ./student-$studentno
        time vagrant --provider=vsphere up student-$studentno-master 2> ./master.error.log 1>master.log
        errors=$(wc -l master.error.log | awk '{print $1}')
        if [ $errors -ne 0 ]
        then
            echo "$(date) creating master for student-$studentno has $errors errors"
        fi
        time vagrant --provider=vsphere up 2> ./error.log 1>log.log
        errors=$(wc -l error.log | awk '{print $1}')
        if [ $errors -ne 0 ]
        then
            echo "$(date) creating minions for student-$studentno has $errors errors"
        fi
        cd ..
    done
fi
