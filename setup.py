"""
Flask-ZeroKAuth
-------------

This is an implementation of srp6a which is a zero-knowledge password protocol.
This means that instead of storing a salted password on your flask site you are instead just recording the minimum amount of information needed for a client to demonstrate that THEY know the password. SRP6 is based off of the hardness of computing discrete log in polynomial time.
"""
from setuptools import setup


setup(
    name='Flask-ZeroKAuth',
    version='0.0.1',
    url='https://github.com/NSkelsey/flask-zerokauth',
    license='BSD',
    author='Nick Skelsey',
    author_email='nskelsey@gmail.com',
    description='A flask srp6 implementation',
    long_description=__doc__,
    packages=['flask_zerokauth'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask'
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
