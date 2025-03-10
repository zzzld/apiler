"""
This module patches python-telegram-bot to work with Python 3.13
"""
import sys
import os

# Add current directory to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Create necessary package structure in sys.modules
if 'telegram.vendor.ptb_urllib3.urllib3.packages.six.moves' not in sys.modules:
    import six_moves
    sys.modules['telegram.vendor.ptb_urllib3.urllib3.packages.six.moves'] = six_moves

if 'urllib3.contrib.appengine' not in sys.modules:
    import appengine
    sys.modules['urllib3.contrib.appengine'] = appengine

# Now import telegram
import telegram

# Return the telegram module for convenience
__all__ = ['telegram'] 