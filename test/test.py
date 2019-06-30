from test_files import shremote as shr

import unittest
import yaml

shr.LOG_DEBUG=False

from test_include_loader import *
from test_fmt_config import *
from test_cfg_loader import *

class TestProgram(unittest.TestCase):

    def setUp(self):
        root_cfg = '''
ssh:
    user: iped
    key: ''
    port: 22

hosts:
    test_host:
        addr: test.com
'''
        dcfg = yaml.load(root_cfg, Loader=yaml.SafeLoader)
        cfg = shr.Config(dcfg)
        shr.Host('test_host', cfg.hosts.test_host)

    def test_defalt_args(self):
        program = dict(
                host = 'test_host',
                start = '{x} {y} {z}',
                defaults = {
                    'x': 'a',
                    'y': 'b',
                    'z': 'c'
                }
        )
        prog_cfg = shr.Config(program)
        prog = shr.Program('test_prog', prog_cfg)
        cmd = prog.cmd().strip()
        self.assertEqual(cmd, 'a b c')

        cmd = prog.cmd(x=1, y=2, z=3).strip()
        self.assertEqual(cmd, '1 2 3')

        cmd = prog.cmd(y=2).strip()
        self.assertEqual(cmd, 'a 2 c')

if __name__ == '__main__':
    unittest.main()
