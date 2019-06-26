import unittest
from config_reader import ConfigFormatter

class TestConfigFormatter(unittest.TestCase):

    def test_full_valid_config(self):
        cfg = {'type': 'map',
                'fields': [{
                'key': 'a',
                'format': {
                        'type': 'map',
                        'fields': [{
                            'key': 'b',
                            'format': {
                                'type': 'str',
                            },
                            'default': 'c',
                            'aliases': ['d','e'],
                            'flags': ['f','g']
                        },{
                            'key': 'h',
                            'format': {
                                    'type': 'str'
                                }
                        }]
                    }
                },{
                    'key': 'b',
                    'format': {
                        'type': 'bool'
                    }
                }]
            }
        ConfigFormatter(cfg)

if __name__ == '__main__':
    unittest.main()
