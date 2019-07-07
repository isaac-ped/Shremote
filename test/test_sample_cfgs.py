import unittest
import test_files
from cfg_loader import load_cfg_file

class TestSampleCfgs(unittest.TestCase):

    def test_default_args(self):
        cfg = load_cfg_file("sample_cfgs/default_args_test.yml")
        self.assertEqual(cfg.commands[0].to_echo.format(), "Hello world!",
                         "Default was not applied")
        self.assertEqual(cfg.commands[1].to_echo.format(), "Goodbye world!",
                         "Default was not overridden")

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
