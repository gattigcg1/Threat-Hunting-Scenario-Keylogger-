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

This is a newly commissioned VM that the manager set up for someone on his team. I suspected that he might have installed some script on the machine that might be allowing him to spy on employees.

I used a query that searches for “FileCreated” Action type using the query below:

```kql
DeviceFileEvents
| where DeviceName contains "win-vm-gcg-321"
| order by Timestamp desc 
| where ActionType == "FileCreated"
| project Timestamp, ActionType, FileName, FolderPath
```

![image](https://github.com/user-attachments/assets/9962ada3-bca0-4575-9c6f-525967a61598)

Looking at the data above, a suspicious looking file called “mykeylogger01.exe” was created on 2025-07-09T12:48:48.8194035Z. It looks like it's nested in this directory: 'C:\Users\gattigcg1\Downloads\Key-Logger-With-Email-master\Key-Logger-With-Email-master\mykeylogger01\obj\Debug\mykeylogger01.exe'. The fact that this an exe file shows that it's a Windows executable file and obj\Debug indicates that this is most likely a C# source file as this is a common folder structure for compiled output in Microsoft Visual Studio projects. Another FileCreated ActionType showed path C:\data\mykeylogger01.exe, which indicates that the file was perhaps copied to this mysterious data folder. 

---

## Summary

It looks like the individual that setup the PC downloaded Visual Studio, created a keylogger script in C# that logs certain button presses to log files, and sends an email after logs get to a certain size to an email. Moreover, a task is scheduled on the PC upon login that launches this script's EXE file silently. This PC was then given to a client that used this PC for work purposes, without realizing at first that the PC had this keylogger software. 

---

## Response Taken

This PC has been wiped and reformatted. The logs were retrieved and sent for further analysis. The matter has been forwarded to upper management, awaiting further guidance. 
