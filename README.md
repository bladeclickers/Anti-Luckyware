# Anti-Luckyware
a c++ program to scan a project for luckyware/darkside

- scans vcxproj for suspicious strings.
- scans for .vs folder and deletes it.
- scans windows sdk file for build stub.
- blocks luckyware links in hosts file.

usage: Anti-Luckyware.exe \<path containing project\>

you can also just run the exe without a project to scan windows sdk and block luckyware links.
