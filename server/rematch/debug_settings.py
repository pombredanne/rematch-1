from settings import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'qvc7t@rd5#1l-n_%%&+_fu+-lu#sp2oonf9mto%bn-1#i7$(tu'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# As of django 1.10, allowed hosts are validated in debug as well,
# this disables that and makes sure all hosts are acceptible when
# running in debug mode. for more details see
# https://docs.djangoproject.com/en/1.10/ref/settings/
# for security implications see
# https://docs.djangoproject.com/en/1.10/topics/security/#host-headers-virtual-hosting
ALLOWED_HOSTS = ['*']
