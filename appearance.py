from workers.coloring import colored, cprint

def print_banner():
	cprint("""
        ___             ___           __         
       / _ \___  __ _  / _ )__ _____ / /____ ____
      / // / _ \/  ' \/ _  / // (_-</ __/ -_) __/
     /____/\___/_/_/_/____/\_,_/___/\__/\__/_/                        
	""", "cyan")

def print_target(domain):
        cprint(" "*16 + "Target: %s \n" % (domain), 
        "green")

def print_error(string):
        print(colored("[!] ", "red") + string)
