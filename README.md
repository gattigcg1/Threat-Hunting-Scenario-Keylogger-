![image](https://github.com/user-attachments/assets/cda9bbe7-c6af-445c-a0cf-a36a1c716ed3)

# Threat-Hunting-Scenario-Keylogger

**Scenario**: A new manager has been hired by Company A named Joe. Joe is a very strict manager that often messages his employees at various times in the day when he feels they might be slacking off. He often makes comments like “Stop goofing off!” even though the employees work remotely. Suspicion has been growing around the office that Joe might somehow be monitoring his employees activities in some fashion. You are tasked with investigating one of the workstations of a member of Joe’s team and seeing if anything unusual is afoot. 

## Platforms and Languages Leveraged
- Windows 10
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Microsoft Visual Studio 2022

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

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

### 2. Looked into the C:\data\ directory and searched the `DeviceNetworkEvents` Table

I investigated several tables trying to find some kind of text file or excel file that was created for the purpose of logging the data. However, this proved hard to find. Perhaps the creation of this logging process file has not been detected by MDE or its in a format that is hard to find. This lead to me investigating the interesting directory: C:\data that was mentioned in the DeviceFileEvents table. 

![image](https://github.com/user-attachments/assets/9f37c1dc-2a86-40cc-af97-b517d9a2f12b)

Looking at C:\data\ on the PC, it's clear that there's two text files. One of them called mylog and the other is called mylog_archive. mylog.txt looks like a file that records user's button presses. This is similarly seen in mylog_archive.txt but the recorded text was seen to be different. The name archive suggests that it could keep some kind of record of past recorded button presses that could get transferred to some location, maybe an offline server.

Looking into DeviceNetworkEvents gives more insights into where these logs could be going. A suspicious record was discovered with InitiatingProcessAccountName is 'amy' which is the account that was created for the employee.

![image](https://github.com/user-attachments/assets/0b3537f0-94a2-4e6d-adfe-91a9f78b42fe)

The RemoteUrl field is 'smtp.gmail.com' which caught my interest. Looking at the record more closely, the script seems to be emailing the log files to an email that can be viewed by the manager because the InitiatingProcessCommandLine field is 'mykeylogger01.exe'. Investigating more into any records with this same RemoteUrl. 

![image](https://github.com/user-attachments/assets/ae9c309e-dc61-4728-a449-d7ef8011ac45)

Two emails were sent with the account name 'amy', and two emails were sent with the user 'gattigcg1' which is the manager's account. It seems like the manager was testing the email functionality of the script right before giving the computer to the employee. 

### 3. Looked into Registry table

What needed investigating was how the script was able to run on Amy's account upon start up/login. Having understanding of the Windows Registry, it would seem like it would be natural that it would be some kind of Task that has been scheduled to run upon login. The manager has not offered access to his account, so we decided to look into MDE and see if we can track the exact time he created the Task. 

Using this query:

```kql
DeviceEvents
| where DeviceName contains "win-vm-gcg-321"
| where ActionType == "ScheduledTaskCreated"
| order by Timestamp desc
```

The field ActionType being ScheduleTaskCreated allows us to see all the tasks that were created. Looking through the records we see a task that mentions 'mykeylogger01.exe' at 2025-07-06T17:06:23.9316582Z. 

![image](https://github.com/user-attachments/assets/c12dabc4-0492-4d71-b0b5-1fd1c6cc5e0e)

Looking at AdditionalFields we get some information about the task that was created by user 'gattigcg1'. While it's not visible in the image, the task action is: Exec\":{\"Command\":\"C:\\\\data\\\\mykeylogger01.exe\" - which clearly shows that its execution of the keylogger script.

---

## Summary

It looks like the individual that setup the PC downloaded Visual Studio, created a keylogger script in C# that logs certain button presses to log files, and sends an email after logs get to a certain size to an email. Moreover, a task is scheduled on the PC upon login that launches this script's EXE file silently. This PC was then given to a client that used this PC for work purposes, without realizing at first that the PC had this keylogger software. 

---

## Response Taken

This PC has been wiped and reformatted. The logs were retrieved and sent for further analysis. The matter has been forwarded to upper management, awaiting further guidance. 
