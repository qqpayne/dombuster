from termcolor import colored

def format_seconds(seconds):
    minutes = seconds // 60
    seconds %= 60
    return colored("[%02i:%02i]" % (minutes, seconds), 'cyan')