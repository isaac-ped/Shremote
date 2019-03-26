import unittest
import shremote as shr
import yaml

shr.LOG_DEBUG=False

def load_raw_cfg(s):
    return yaml.load(s, shr.Loader)

class TestLoader(unittest.TestCase):

    def test_full_import(self):
        cfg = '''
imported: !import test_include.yml
'''
        raw_cfg = yaml.load(cfg, shr.Loader)
        included_cfg = yaml.load(open('test_include.yml'), shr.Loader)

        self.assertEqual(raw_cfg['imported'], included_cfg)

    def test_1_partial_import(self):
        cfg = '''
imported: !import test_include.yml::entry_one
'''
        raw_cfg = yaml.load(cfg, shr.Loader)
        included_cfg = yaml.load(open('test_include.yml'), shr.Loader)

        self.assertEqual(raw_cfg['imported'], included_cfg['entry_one'])

    def test_2_partial_import(self):
        cfg = '''
imported: !import test_include.yml::entry_one::sub_key1
'''
        raw_cfg = yaml.load(cfg, shr.Loader)
        included_cfg = yaml.load(open('test_include.yml'), shr.Loader)

        self.assertEqual(raw_cfg['imported'], included_cfg['entry_one']['sub_key1'])

    def test_dne_import(self):
        cfg = '''
imported: !import test_include.yml::entry_one::NONEXISTENT_KEY2
'''
        try:
            raw_cfg = yaml.load(cfg, shr.Loader)
            self.assertTrue(False, "Importing nonexistent key did not fail")
        except shr.ImportException:
            pass

    def test_inherit_no_override(self):
        cfg = '''
inherited: !inherit |
    test_include.yml::entry_one
'''
        raw_cfg = yaml.load(cfg, shr.Loader)
        included_cfg = yaml.load(open('test_include.yml'), shr.Loader)

        self.assertEqual(raw_cfg['inherited'], included_cfg['entry_one'])

    def test_inherit_override(self):
        cfg = '''
inherited: !inherit |
    test_include.yml::entry_one
    sub_key2: new_value2
'''
        raw_cfg = yaml.load(cfg, shr.Loader)
        included_cfg = yaml.load(open('test_include.yml'), shr.Loader)

        self.assertEqual(raw_cfg['inherited']['sub_key1'],
                         included_cfg['entry_one']['sub_key1'])

        self.assertEqual(raw_cfg['inherited']['sub_key2'], 'new_value2')

    def test_inherited_merge(self):
        cfg = '''
inherited: !inherit |
    test_include.yml
    entry_one:
        sub_key2: new_value2
        sub_key3: new_value3
'''
        raw_cfg = yaml.load(cfg, shr.Loader)
        included_cfg = yaml.load(open('test_include.yml'), shr.Loader)

        self.assertEqual(raw_cfg['inherited']['entry_one']['sub_key1'],
                         included_cfg['entry_one']['sub_key1'])
        self.assertEqual(raw_cfg['inherited']['entry_one']['sub_key2'],
                         'new_value2')
        self.assertEqual(raw_cfg['inherited']['entry_one']['sub_key3'],
                         'new_value3')

class TestConfig(unittest.TestCase):

    def tearDown(self):
        shr.Config.clear_instance()

    def test_eval_format(self):
        eval_cfg = '''
x: 5
five_as: $('a' * 5)
ten: $({0.x} * 2)
'''
        raw_cfg = load_raw_cfg(eval_cfg)
        cfg = shr.Config(raw_cfg)

        x = cfg.formatted("five_as")
        self.assertEqual(x, 'a'*5)

        x = cfg.formatted("ten")
        self.assertEqual(x, 10)

    def test_no_eval_format(self):
        no_eval_cfg = '''
x: $$(foobar)
y: $$({0.x})
'''
        raw_cfg = load_raw_cfg(no_eval_cfg)
        cfg = shr.Config(raw_cfg)

        x = cfg.formatted('x')
        self.assertEqual(x, '$(foobar)')

        x = cfg.formatted('y')
        self.assertEqual(x, '$($(foobar))')


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
