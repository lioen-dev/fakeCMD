import os
import ctypes
import time
import random

ctypes.windll.kernel32.SetConsoleTitleW("Command Prompt")

user = os.getlogin()
unstopped = True

os.chdir(f"C:\\Users\\{user}")

def n():
    print()

def shell():
    # Display shell prompt with the current directory and take user input
    print("")
    return input(f"{os.getcwd()}>")

def thatdidntwork():
    print(f"'{choice}' is not recognized as an internal or external command,")
    print("operable program or batch file.")

print("Microsoft Windows [Version 10.0.22631.4391]")
print("(c) Microsoft Corporation. All rights reserved.")

while True:
    choice = shell()

    if choice == "":
        continue

    if choice == "exit":
        exit()

    elif choice == "cls": 
        os.system("cls")

    elif choice == "dir":
        os.system("dir")
        print("All files scanned to be safe!")

    elif choice.startswith("echo"):
        message = choice[len("echo "):]
        print(message)

    elif choice.startswith("cd"):
        try:
            path = choice[3:].strip()
            if path == "":
                os.chdir(os.path.expanduser("~"))
            else:
                os.chdir(path)
                
        except FileNotFoundError:
            print(f"The system cannot find the path specified: '{path}'")

    elif choice == "tree":
        willitrun = random.randint(0,7)
        if willitrun > 1:
            os.chdir(f"C:\\Users\\{user}")
            os.system('tree')
            n()
            print("All Files addresses scanned. Results Below.")
            n()
            print("Safe Files: 8")
            print("Suspicious Files: 0")
            print("Dangerous Files: 0")
        else:
            thatdidntwork()

    elif choice == "netstat":
        willitrun = random.randint(0,7)
        if willitrun > 1:
            print("Active Connections")
            print(f"  Proto  Local Address          Foreign Address        State")
            print(f"  TCP    127.0.0.1:6327         {user}:49304            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:6327         {user}:49362            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:6327         {user}:53186            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:6327         {user}:53187            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:6327         {user}:53189            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:6327         {user}:53229            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:6327         {user}:53235            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:6327         {user}:53237            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:27060        {user}:57344            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:49304        {user}:6327             ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:57300        {user}:57316            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:57301        {user}:57315            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:57315        {user}:57301            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:57316        {user}:57300            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:57344        {user}:27060            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:57945        {user}:52985            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    127.0.0.1:58219        {user}:53185            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            print(f"  TCP    192.168.0.23:65001        {user}:52769            ESTABLISHED (Confirmed by Microsoft as SAFE!)")

            try:
                while True:
                    time.sleep(random.randint(0,10))
                    randomport = random.randint(00000,99999)
                    random2digit = random.randint(00,99)
                    print(f"  TCP    127.0.0.1:{randomport}        sea{random2digit}s{random2digit}-in-f4:https            ESTABLISHED (Confirmed by Microsoft as SAFE!)")
            except KeyboardInterrupt:
                print("")
                os.system("cls")
        else:
            thatdidntwork()

    elif choice == "ipconfig":
        willitrun = random.randint(0,7)
        if willitrun > 1:
            os.system('ipconfig')
            n()
            print("All IP addresses scanned. Results Below.")
            n()
            print("Safe Connections: 8")
            print("Suspicious Connections: 0")
            print("Dangerous Connections: 0")
        else:
            thatdidntwork()

    elif choice == "assoc":
        willitrun = random.randint(0,7)
        if willitrun > 1:
            os.system('assoc')
            n()
            print("All file associations scanned. Results below.")
            n()
            print("Safe Files: 403")
            print("Suspicious Files: 0")
            print("Dangerous Files: 0")
        else:
            thatdidntwork()

    elif choice == "chkdsk":
        willitrun = random.randint(0,7)
        if willitrun > 1:
            print("The type of the file system is NTFS.")
            time.sleep(1)
            print("Running CHKDSK in read-only mode.")
            print("Stage 1: Examining basic file system structure ...")
            print("  1670400 file records processed.")
            print("File verification completed.")
            print(" Phase duration (File record verification): 7.52 seconds.")
            print("  29481 large file records processed.")
            print(" Phase duration (Orphan file record recovery): 12.82 milliseconds.")
            print("  0 bad file records processed.")
            print(" Phase duration (Bad file record checking): 0.32 milliseconds.")
            n()
            print("No harmful files found!")
            n()
            time.sleep(1)
            print("Stage 2: Examining file name linkage ...")
            print("  958 reparse records processed.")
            print("  2143194 index entries processed.")
            print("Index verification completed.")
            print(" Phase duration (Index verification): 21.22 seconds.")
            print("CHKDSK is scanning unindexed files for reconnect to their original directory.")
            n()
            print("No harmful files found!")
            n()
            time.sleep(1)
            print("Stage 3: Examining security descriptors ...")
            print("Security descriptor verification completed.")
            print(" Phase duration (Security descriptor verification): 40.16 milliseconds.")
            print("  236398 data files processed.")
            print(" Phase duration (Data attribute verification): 0.54 milliseconds.")
            print("CHKDSK is verifying Usn Journal...")
            print("Usn Journal verification completed.")
            n()
            print("Windows has checked the file system and found no problems!")
            n()
            print("1298853452 KB total disk space.")
            print(" 819373356 KB in 983299 files.")
            print("    624408 KB in 236399 indexes.")
            print("         0 KB in bad sectors.")
            print("   1827936 KB in use by the system.")
            print("     65536 KB occupied by the log file.")
            print(" 477027752 KB available on disk.")
            n()
            print("      4096 bytes in each allocation unit.")
            print(" 324713363 total allocation units on disk.")
            print(" 119256938 allocation units available on disk.")
            n()
            print("Total duration: 45.23 seconds (45233 ms).")

    elif choice == "msconfig":
        thatdidntwork()

    elif choice == "whoami":
        print("User/SCAMMER001")

    elif choice.startswith("ping"):
        print("Pinging secure IP Address...")
        time.sleep(random.randint(3,7))
        print("No viruses or hackers found!")

    else:
        os.system(choice)