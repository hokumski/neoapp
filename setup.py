"""
Neoapp - boilerplate class for handling requests signed with OpenID JWT token
"""

from setuptools import setup, find_packages

setup(
    name='neoapp',
    version='1.0.0',
    packages=find_packages(),
    url='https://github.com/hokumski/neoapp',
    license='',
    author='Andrey Kotov',
    author_email='hokum@dived.me',
    description='Neoapp',
    include_package_data=True,
    install_requires=[
        'requests',
        'base58',
        'ecdsa'
    ]
)