import unittest
import test_files
import os
import shutil
from cfg_loader import load_cfg_file
from shremote import ShRemote

class TestSampleCfgs(unittest.TestCase):

    TEST_OUTPUT_DIR='test_output'

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.TEST_OUTPUT_DIR, ignore_errors=True)

    def test_all_sample_cfgs(self):
        cfgs = [
            'simple_cfg.yml',
            'default_args_test.yml',
            'test_computed_fields.yml',
            'test_escaped_computation.yml',
            'test_escaped_reference.yml'
        ]

        for cfg in cfgs:
            ShRemote(os.path.join('sample_cfgs', cfg), 'cfg_test', self.TEST_OUTPUT_DIR, {})

    def test_default_args(self):
        cfg = load_cfg_file("sample_cfgs/default_args_test.yml")
        start1 = cfg.commands[0].to_echo.format(host=cfg.commands[0].hosts[0])
        self.assertEqual(start1, "Hello world!", "Default was not applied")
        start2 = cfg.commands[1].to_echo.format(host=cfg.commands[1].hosts[0])
        self.assertEqual(start2, "Goodbye local", "Default was not overridden,  instead: %s" % start2)

    def test_computed_fields(self):
        cfg = load_cfg_file("sample_cfgs/test_computed_fields.yml")
        self.assertEqual(cfg.commands[0].begin.format(), 42,
                         "Begin (numerical) computation not applied")
        self.assertEqual(cfg.commands[0].to_echo.format(), 'x' * 42,
                         "to_echo (str) computation not applied")
        self.assertEqual(cfg.commands[0].program.start.format(), 'echo "%s"' % ('x' * 42),
                         "program.start (str reference) computation not applied")


    def test_escaped_computed_fields(self):
        cfg = load_cfg_file("sample_cfgs/test_escaped_computation.yml")
        self.assertEqual(cfg.commands[0].computed.format(), 'x' * 42,
                         "Computed field not set properly")
        escaped = cfg.commands[0].escaped.format()
        self.assertEqual(escaped, "$( 'x' * 10 )",
                         "Escaped computation not properly evaluated: {}".format(escaped))
        referenced = cfg.commands[0].referenced.format()
        self.assertEqual(referenced, "$( 'x' * 10 )",
                         "referenced computation not properly evaluated: {}".format(referenced))

    def test_escaped_reference(self):
        cfg = load_cfg_file("sample_cfgs/test_escaped_reference.yml")
        self.assertEqual(cfg.commands[0].reference.format(), 'ref',
                         "Referenced field not substituted")
        escaped = cfg.commands[0].escaped.format()
        self.assertEqual(escaped, "{0.referenceable}",
                         "Escaped reference not properly formatted: {}".format(escaped))
        self.assertEqual(cfg.commands[0].dne.format(), "{0.DNE}",
                         "Escaped DNE reference not properly formatted")
        escaped = cfg.commands[0].escaped_reference.format()

        self.assertEqual(escaped, "{0.referenceable}",
                         "Reference to escaped not properly formatted: {}".format(escaped))

if __name__ == '__main__':
    unittest.main()
