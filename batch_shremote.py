import subprocess
import sys
import os
import time

if __name__ == '__main__':
    print("Going to run {}".format(sys.argv[1:]))
    time.sleep(10)
    for file in sys.argv[1:]:
        label = os.path.basename(os.path.splitext(file)[0])
        cmd = ['python', 'shremote.py', file, label, '--export', 'EXPORT_LOC']
        print('Running {}'.format(cmd))
        subprocess.call(cmd)
        print("Done")
        time.sleep(10)
