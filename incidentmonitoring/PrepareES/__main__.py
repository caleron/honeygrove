import os
import sys

from PrepareES.PrepareES import readyToMap

sys.path.append(os.path.abspath(__file__ + "/.."))

if __name__ == '__main__':
    # Start the mapping process
    print('\033[94m' + "Start Mapping..." + '\033[0m')
    readyToMap()
