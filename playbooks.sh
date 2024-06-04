#!/bin/sh

sed -i s/INSERTIPADDRESS/$1/g $3/*.md
sed -i s/INSERTHOSTNAME/$2/g $3/*.md
echo "Updated All Available Playbooks for $2" 

## Create Obsidian Preaction to Prompt for IP and Hostname and map both back to the {{_ip_address}} {{_machine_name}}
## Then create Obsidian Shell Commands with one of the Vaules shown below (Path is dependant where the button is published) 
## /bin/bash {{folder_path:absolute}}/../player.sh {{_ip_address}} {{_machine_name}} "{{folder_path:absolute}}/Machines/{{_machine_name}}/"
## /bin/bash {{folder_path:absolute}}/../../../player.sh {{_ip_address}} {{_machine_name}} "{{folder_path:absolute}}"
