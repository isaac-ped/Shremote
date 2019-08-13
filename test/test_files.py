import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import include_loader
import fmt_config
import cfg_format
import logger

logger.set_test_mode()
