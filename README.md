CMA http://teawater.github.io/cma/
===
<div style="text-align: center;">
<a href="indexcn.html">Chinese</a><br>
</div>
<br>
<table
style="text-align: left; width: 60%; margin-left: auto; margin-right: auto;"
border="1" cellpadding="0" cellspacing="0">

<tr align="center">
<td style="vertical-align: top;">What is CMA?<br>
</td>
</tr>
<tr>
<td style="vertical-align: top;">A GDB Python script that analyzes and records C/C++ application's dynamic memory status.<br>CMA has little effect on analyzed C/C++ application performance. <br>
CMA supports X86_32 and X86_64.
</td>
</tr>
<tr align="center">
<td style="vertical-align: top;"><br>
</td>
</tr>
<tr align="center">
<td style="vertical-align: top;">How to use CMA?<br>
</td>
</tr>
<tr>
<td style="vertical-align: top;">
<ol>
   <li> CMA just can work with GDB 7.5 or newer version.  You can use <a href="http://teawater.github.io/get-gdb/">Get-GDB</a> check the version of GDB in current system and get GDB 7.5 or newer version if need.
<table
style="text-align: left; width: 90%;"
border="0" cellpadding="0" cellspacing="0">
<tbody>
<tr>
<td style="vertical-align: top; background-color: rgb(238, 238, 238);">
wget https://raw.githubusercontent.com/teawater/get-gdb/master/get-gdb.py<br>
python get-gdb.py
</td>
</tbody>
</table>
</li>
   <li> Get CMA.
<table
style="text-align: left; width: 90%;"
border="0" cellpadding="0" cellspacing="0">
<tbody>
<tr>
<td style="vertical-align: top; background-color: rgb(238, 238, 238);">
wget https://raw.githubusercontent.com/teawater/cma/master/cma.py
</td>
</tbody>
</table>
</li>

<li>
C/C++ application that want to analyzes should be built with GCC "-g" option to get the memory allocate and release code line infomation.
<table
style="text-align: left; width: 90%;"
border="0" cellpadding="0" cellspacing="0">
<tbody>
<tr>
<td style="vertical-align: top; background-color: rgb(238, 238, 238);">
gcc -g xxx<br>
g++ -g xxx
</td>
</tbody>
</table>
</li>

<li>
GDB control the C/C++ application that want to analyzes.<br>
There are some ways:
<ul>
   <li> Open GDB with a application.  Don't need execute application because CMA script will auto do it if need.
<table
style="text-align: left; width: 90%;"
border="0" cellpadding="0" cellspacing="0">
<tbody>
<tr>
<td style="vertical-align: top; background-color: rgb(238, 238, 238);">
gdb xxx
</td>
</tbody>
</table>
</li>
<li>
Attach a running application.
<table
style="text-align: left; width: 90%;"
border="0" cellpadding="0" cellspacing="0">
<tbody>
<tr>
<td style="vertical-align: top; background-color: rgb(238, 238, 238);">
gdb -p pid
</td>
</tbody>
</table>
Or
<table
style="text-align: left; width: 90%;"
border="0" cellpadding="0" cellspacing="0">
<tbody>
<tr>
<td style="vertical-align: top; background-color: rgb(238, 238, 238);">
gdb<br>
attach pid
</td>
</tbody>
</table>

</li>
 </ul>
</li>

<li>
Start CMA script inside GDB.<br>
It will let you input some options.  Then, exencute application and analyzes its memory allocate and release.
<table
style="text-align: left; width: 90%;"
border="0" cellpadding="0" cellspacing="0">
<tbody>
<tr>
<td style="vertical-align: top; background-color: rgb(238, 238, 238);">
source cma.py
</td>
</tbody>
</table>
</li>

<li>
When CMA script and application is running, you can use CTRL-C interrupt their execution. Then, you can let CMA script save record to a CSV file.<br>
CSV file can be read by Openoffice or Excel.
<table
style="text-align: left; width: 90%;"
border="0" cellpadding="0" cellspacing="0">
<tbody>
<tr>
<td style="vertical-align: top; background-color: rgb(238, 238, 238);">
[0] Record memory infomation to "/home/teawater/tmp/cma.csv".<br>
[1] Continue.<br>
[2] Quit.<br>
Which operation?[0]<br>
Memory infomation saved into "/home/teawater/tmp/cma.csv".<br>
Continuing.
</td>
</tbody>
</table>
</li>
</ol>
</td>
</tr>


<tr align="center">
<td style="vertical-align: top;"><br>
</td>
</tr>

<tr align="center">
<td style="vertical-align: top;">Screenshot<br>
</td>
</tr>

<tr align="center">
<td style="vertical-align: top;">This is a screenshot of a CSV file.<br>
<a href="http://teawater.github.io/cma/eb.png"><IMG src="http://teawater.github.io/cma/es.png" align="" border="0"></a>
</td>
</tr>

</tbody>
</table>
