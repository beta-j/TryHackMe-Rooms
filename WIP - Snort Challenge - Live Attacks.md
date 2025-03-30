# Snort Challenge - The Basics
---
**Description:** Put your snort skills into practice and write snort rules to analyse live capture network traffic.

**Difficulty:** Medium

**Link**: [https://tryhackme.com/r/room/snortchallenges1](https://tryhackme.com/r/room/snortchallenges1)


## CONTENTS
- [Task 1 - INTRODUCTION](#task-1---introduction)
- [Task 2 - WRITING IDS RULES (HTTP)](#task-2--writing-ids-rules-http)
- [Task 3 - WRITING IDS RULES (FTP)](#task-3--writing-ids-rules-ftp)
- [Task 4 - WRITING IDS RULES (PNG)](#task-4--writing-ids-rules-png)
- [Task 5 - WRITING IDS RULES (Torrent Metafile)](#task-5---writing-ids-rules-torrent-metafile)
- [Task 6 - TROUBLESHOOTING RULE SYNTAX ERRORS](#task-6---troubleshooting-rule-syntax-errors)
- [Task 7 - USING EXTERNAL RULES (MS17-010)](#task-7---using-external-rules-ms17-010)
- [Task 8 - USING EXTERNAL RULES (Log4j)](#task-8---using-external-rules-log4j)


---
## Task 1 - INTRODUCTION

Simply click on the **Start Machine** button to launch the VM you will be using for this task and wait fo it to load.

---

## Task 2- WRITING IDS RULES (HTTP)

For this task we are provided with two files inside the folder `TASK-2 (HTTP)`  

```console
ubuntu:~/Desktop/Exercise-Files$ cd TASK-2\ \(HTTP\)/
ubuntu:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ ls
local.rules  mx-3.pcap
