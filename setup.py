from __future__ import absolute_import
from distutils.core import setup

setup(
    name="Spylib",
    version="v0.0.4",
    packages=["src"],
    long_description=open("README.md").read(),
    install_requires=["requests>=2.0.0", "PyJWT>=1.7.1"],
)
