# WinAce-POC
Simple POC to leverage CVE-2018-20250 from inside an EXE


# To-Do
- [ ] Parse the ACE header file, to be able to change the destination Path (ex. add C:\Users\\<userName\>\...) and fix the CRC (this way the path of the dropper wouldn't dependent on the path of the execution)
- [ ] Look a way to use a File Mapping as the param to ACEExtract, these way we avoid having to drop the ACE file into disk

# Notes & Disclaimers
After reading this great article (https://research.checkpoint.com/extracting-code-execution-from-winrar/) from CheckPoint I though I would be cool to try an exploit the vuln from inside an EXE. I **totally know this is useless, because if you can execute an EXE inside a compromised machine you already got an RCE so you don't really need to use this technique at all**. You could just do ```CreateFile(StartupFolder,...) ``` and directly drop a file there. Anyway it's always fun to look for new ways to drop a file in the system.

There are almost no checks inside the code, it's just written as a quick POC so be aware of that if you intend to use it or try it. Same applies to the loader, if you plan on using it make sure to add some checks (also there is a weird thing on the export directory of UNACEV2.DLL that makes functions, names and ordinals arrays to not be parallel so I had to do a little hack there have this in mind If you want to use the ```GetExportedFunction``` function with other DLL)

Lastly, the code basically will search for the DLL file in the resources (resources are encrypted with a simple xor and a base64, just for fun :P), load it, then decrypt the ACE files from the resources and call the function ACEExport from the UNACEV dll (Make sure to check this awesome project https://github.com/FarGroup/FarManager, from which I borrowed some Headers, alongside with the Checkpoint post)

To create the vulnerable ACE file you can use this excellent tool https://github.com/WyAtu/CVE-2018-20250
