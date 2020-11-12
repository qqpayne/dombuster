import sys

colors = {
    'black': '\033[30m',
    'red': '\033[31m',
    'green': '\033[32m',
    'yellow': '\033[33m',
    'blue': '\033[34m',
    'magnetta': '\033[35m',
    'cyan': '\033[36m',
    'white': '\033[37m',
    'native': '\033[0m',
}

is_windows = sys.platform.startswith('win')

def colored(string, color):
    if (is_windows):
        return string

    return "%s %s %s" % (colors.get(color), string, colors.get('native'))

def cprint(string, color):
    print(colored(string, color))