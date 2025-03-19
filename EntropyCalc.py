import sys
import math
import pefile

# output the entropy of specific data 'buffer'
def calc_entropy(buffer):
    if isinstance(buffer, str):
        buffer = buffer.encode()
    entropy = 0
    for x in range(256):
        p = (float(buffer.count(bytes([x])))) / len(buffer)
        if p > 0:
            entropy += - p * math.log(p, 2)
    return entropy

# print help
def printhelp():
    print("[i] Usage:\n" + 
          "\t- python.exe EntropyCalc.py <filename>\n" +
          "\t- python.exe EntropyCalc.py <-pe> <pe filename>")
    sys.exit(1)
    

# output the entropy of the file as a whole
def calc_file_entropy(filename):
    try:
        with open(filename, "rb") as f:
            buf = f.read()
            entropy = calc_entropy(buf)
            print(f"Entropy Of {filename} As A Whole File Is : {entropy:.5f}")
    except FileNotFoundError:
        print(f"[!] Error: \"{filename}\" Is Not A Valid File")
        printhelp()



# if input is only the file's name 
if len(sys.argv) == 2:
        calc_file_entropy(sys.argv[1])
        sys.exit(1)

# else if input is with the "-pe" argument
elif len(sys.argv) == 3 and sys.argv[1] == "-pe":
    try:
        PEfile = pefile.PE(sys.argv[2])
        print(f"[i] Parsing {sys.argv[2]}'s PE Section Headers ... ")
        for section in PEfile.sections:
            name = section.Name.rstrip(b'\x00').decode()
            entropy = calc_entropy(section.get_data())
            color_code = 31 + (hash(name) % 6)  # choose color based on section name
            print(f"\t>>> \033[{color_code}m\"{name}\"\033[0m Scored Entropy Of Value: \033[{color_code}m{entropy:.5f}\033[0m")
    except FileNotFoundError:
        print(f"[!] Error: \"{sys.argv[2]}\" Is Not A Valid File")
        printhelp()
    except pefile.PEFormatError:
        print(f"[!] Error: \"{sys.argv[2]}\" Is Not A Valid PE File")
        printhelp()
            
else:
    printhelp()
    

    