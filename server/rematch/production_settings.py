import os

from settings import *

# Debug setting exposes internal information on errors, this should be avoided
# for production deployments where attackers might encounter details that might
# harm the server and users' security
DEBUG = False

# SECRET_KEY must be kept secret, so it is not included in the repository for
# production servers and instead auto-generated and saved to disk on first run
SETTINGS_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY_PATH = os.path.join(SETTINGS_DIR, '.rematch_secret.key')
if not os.path.isfile(SECRET_KEY_PATH):
  fd = os.open(SECRET_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
  try:
    with os.fdopen(fd, 'w') as fh:
      import django.core.management.utils
      fh.write(django.core.management.utils.get_random_secret_key())
  except Exception:
    os.unlink(SECRET_KEY_PATH)

with open(SECRET_KEY_PATH, 'r') as fh:
  SECRET_KEY = fh.read()
assert len(SECRET_KEY) > 20
