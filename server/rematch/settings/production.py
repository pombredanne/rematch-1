from rematch.settings.base import *  # NOQA: F401, F403

# Debug setting exposes internal information on errors, this should be avoided
# for production deployments where attackers might encounter details that might
# harm the server and users' security
DEBUG = False
