# ADEnum.ps1 :
An updated version of the [ADEnum.ps1](https://github.com/0xb1tByte/CRTP-Journey/tree/main/Scripts) script . The script enumerates the required information at the forest level (enumerating domains within the forest)

## Sample Outputs :

![alt text](https://github.com/0xb1tByte/CRTE-Journey/blob/main/Scripts/1.png)
![alt text](https://github.com/0xb1tByte/CRTE-Journey/blob/main/Scripts/2.png)
![alt text](https://github.com/0xb1tByte/CRTE-Journey/blob/main/Scripts/3.png)
![alt text](https://github.com/0xb1tByte/CRTE-Journey/blob/main/Scripts/5.png)
![alt text](https://github.com/0xb1tByte/CRTE-Journey/blob/main/Scripts/4.png)



# NestedGroupsACLs.ps1
A simple script to automate the task of finding **Interesting ACLs** of **Nested Groups** of a user. The script is relying on the following tools: 
- PowerView.ps1

## Usage : 
``NestedGroupsACLs <username>``

# Notes :
- The main purpose of these scripts is to automate manual commands and to get familiar with **Windows Powershell scripting** 
- The scripts were tested in the **Advanced Red Team Lab (CRTE)** and in **Penetration Testing Extreme v2 Lab **
- The network noise of the scripts has not been tested
