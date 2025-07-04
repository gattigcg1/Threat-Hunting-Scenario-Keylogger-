![image](https://github.com/user-attachments/assets/cda9bbe7-c6af-445c-a0cf-a36a1c716ed3)

# Threat-Hunting-Scenario-Keylogger

**Scenario**: A new manager has been hired by Company A named Joe. Joe is a very strict manager that often messages his employees at various times in the day when he feels they might be slacking off. He often makes comments like “Stop goofing off!” even though the employees work remotely. Suspicion has been growing around the office that Joe might somehow be monitoring his employees activities in some fashion. You are tasked with investigating one of the workstations of a member of Joe’s team and seeing if anything unusual is afoot. Company A has been noticing some PII information about employees might be getting leaked because of recent phishing attempts that have been perpetrated. Such information includes address, email address, and phone number. All of this information is stored on a linux server as a hidden file where only the root/sudo users have read and write access. There was a report by another employee the other day of a fellow employee messing with the computer while the root administrator was in the bathroom. The company has decided to investigate this.

## Platforms and Languages Leveraged
- Windows 10
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Microsoft Visual Studio 2022

---

## Steps Taken

This is a newly commissioned VM that the manager set up for someone on his team. I suspected that he might have installed some script on the machine that might be allowing him to spy on employees. Looked at 

I used a query that searches for “FileCreated” Action type using the query below:

```kql
DeviceFileEvents
| where DeviceName contains "VM_HOST_NAME"
| where ActionType == "FileCreated"
```

![image](https://github.com/user-attachments/assets/1f0bab05-024a-4ce3-9ae5-49161234803a)

Looking at the data above, a suspicious looking file called “super_secret_script.sh” was created on 2025-06-16T12:20:50.902852Z. There are two rows that have this filename, after investigating the contents we find the differences as follows:

![image](https://github.com/user-attachments/assets/93aaed82-dc30-46ae-ba9b-3d41baac883a)

Touch is a linux command that creates the super_secret_script.sh while nano command opens said file in the nano text editor in Linux. 

This is the first most interesting thing, but let's also look in this table and see if there’s anything else interesting. 

DeviceFileEvents
| where DeviceName contains "VM_HOST_NAME"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp asc

![image](https://github.com/user-attachments/assets/3453d6d7-d3a0-4ce7-be86-0e7ac6ffb3f1)

InitialProcessCommandLine gives us more insight into what effects could be had on the VM. After the command “nano super_secret_script.sh”, we see one more interesting row. “usermod -aG sudo john_smith” which is very suspicious as it gives the user John Smith sudo privileges, which is a backdoor into the system. The door is closing in! 

---

## Summary

It looks like the individual that setup the PC downloaded Visual Studio, created a keylogger script in C# that logs certain button presses to log files, and sends an email after logs get to a certain size to an email. Moreover, a task is scheduled on the PC upon login that launches this script's EXE file silently. This PC was then given to a client that used this PC for work purposes, without realizing at first that the PC had this keylogger software. 

---

## Response Taken

This PC has been wiped and reformatted. The logs were retrieved and sent for further analysis. The matter has been forwarded to upper management, awaiting further guidance. 
