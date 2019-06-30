import unittest
import os
import yaml
import test_files ## Adds path to import cfg_loader
from cfg_loader import CfgLoader, DEFAULT_CFG_FMT_FILE

class TestCfgLoader(unittest.TestCase):

    def test_load_default_format(self):
        with open(DEFAULT_CFG_FMT_FILE, 'r') as f:
            cfg_fmt = yaml.load(f, yaml.SafeLoader)
        CfgLoader(cfg_fmt)

if __name__ == '__main__':
    unittest.main()
