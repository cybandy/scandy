from scandyCore import ScandyCore
import sys
from termcolor import colored



def main():
    try:
        f = ScandyCore()
    except PermissionError:
        sys.exit(f"\n{colored( 'Run the program with sudo or administrator priveledges','red')}")


if __name__=='__main__':
    main()