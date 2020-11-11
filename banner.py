import sys

CYAN = '\033[36m'  # cyan
NATIVE_COLOR = '\033[0m'   # native color

is_windows = sys.platform.startswith('win')
if (is_windows):
    try:
        import colorama
        colorama.init()
    except:
        CYAN = NATIVE_COLOR = ''


def print_banner():
	print("""%s 
         ___             ___           __         
        / _ \___  __ _  / _ )__ _____ / /____ ____
       / // / _ \/  ' \/ _  / // (_-</ __/ -_) __/
      /____/\___/_/_/_/____/\_,_/___/\__/\__/_/       
                                     
	%s""" % (CYAN, NATIVE_COLOR))
