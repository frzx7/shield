import psutil

# Measuring power of computer
def detect_mode() -> str:
    ram_gb = psutil.virtual_memory().total / (1024 ** 3)        #gets capacity of RAM and converts it to GB
    if ram_gb < 6:                  #if computer ram is
        return "lite"
    if ram_gb < 12:
        return "standard"
    return "full"
