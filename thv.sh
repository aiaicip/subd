#!/bin/bash

apt-get update

apt-get install git -y
clear

apt-get install python-pip -y

pip install requests

git clone https://github.com/laramies/theHarvester.git

ls

cd theHarvester/

ls

chmod +x theHarvester.py

ls

./theHarvester.py
