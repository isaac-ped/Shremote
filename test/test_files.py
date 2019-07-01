import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import shremote
import cfg_loader
import include_loader
import fmt_config
import logger

logger.set_test_mode()
