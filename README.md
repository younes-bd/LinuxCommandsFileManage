<h1>File permissions in Linux </h1>

<h2>Description</h2>
The research team at my organization needs to update the file permissions for certain files and directories within the projects directory. The permissions do not currently reflect the level of authorization that should be given. Checking and updating these permissions will help keep their system secure. To complete this task, I performed the following tasks:
<br />


<h2>Languages and Utilities Used</h2>

- <b>PowerShell</b> 
- <b>Diskpart</b>

<h2>Environments Used </h2>

- <b>Windows 10</b> (21H2)

<h2>Program walk-through:</h2>

<p align="center">
Check file and directory details: <br/>
 The following code demonstrates how I used Linux commands to determine the existing permissions set for a specific directory in the file system.
 <br/>
 <br/>
 <img src="https://i.imgur.com/dPlSonb.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 The first line of the screenshot displays the command I entered, and the other lines display the output. The code lists all contents of the projects directory. I used the ls command with the -la option to display a detailed listing of the file contents that also returned hidden files. The output of my command indicates that there is one directory named drafts, one hidden file named .project_x.txt, and five other project files. The 10-character string in the first column represents the permissions set on each file or directory.
 
<p align="center">
Check file and directory details: <br/>
 The following code demonstrates how I used Linux commands to determine the existing permissions set for a specific directory in the file system.
 <br/>
 <br/>
<img src="https://i.imgur.com/dPlSonb.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
<p align="center">
Check file and directory details: <br/>
 The following code demonstrates how I used Linux commands to determine the existing permissions set for a specific directory in the file system.
 <br/>
 <br/>
<img src="https://i.imgur.com/dPlSonb.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
<p align="center">
Check file and directory details: <br/>
 The following code demonstrates how I used Linux commands to determine the existing permissions set for a specific directory in the file system.
 <br/>
 <br/>
 <img src="https://i.imgur.com/dPlSonb.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
<p align="center">
Check file and directory details: <br/>
 The following code demonstrates how I used Linux commands to determine the existing permissions set for a specific directory in the file system.
 <br/>
 <br/>
 <img src="https://i.imgur.com/dPlSonb.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
<p align="center">
Check file and directory details: <br/>
 The following code demonstrates how I used Linux commands to determine the existing permissions set for a specific directory in the file system.
 <br/>
 <br/>
 <img src="https://i.imgur.com/dPlSonb.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
<p align="center">
Check file and directory details: <br/>
 The following code demonstrates how I used Linux commands to determine the existing permissions set for a specific directory in the file system.
 <br/>
 <br/>
 <img src="https://i.imgur.com/dPlSonb.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
