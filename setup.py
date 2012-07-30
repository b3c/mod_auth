__author__ = 'Alfredo Saglimbeni'
__mail__ = "repirro@gmail.com"


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

#!/usr/bin/env python
from setuptools import  find_packages

METADATA = dict(
    name='mod_auth_library',
    version='1.0',
    author='Alfredo Saglimbeni',
    author_email='a.saglimbeni@scsitaly.com, repirro@gmail.com',
    description='Powerfull and useful library to integrate mod_auth_tkt and mod_auth_pubtkt into your projects.',
    long_description=open('./README.txt').read(),
    url='https://github.com/b3c/mod_auth',
    license = "BSD",
    keywords='mod_auth mod_auth_pubtkt mod_auth_tkt authentication single sign on ticket',
    install_requires=['M2Crypto','pycrypto'],
    include_package_data=True,
    classifiers=[
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'Environment :: Web Environment',
        'Topic :: Internet',
        'Operating System :: OS Independent',
        ],
    zip_safe=False,
    packages=find_packages(),
)

if __name__ == '__main__':
    setup(**METADATA)

