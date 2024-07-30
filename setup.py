from setuptools import setup, find_packages


VERSION = '0.1.0'
DESCRIPTION = 'Pull only necessary code snippets from a script'


setup(

    name="ze_vacuum", 
    version=VERSION,
    author="mOmE",
    description=DESCRIPTION,
    packages=find_packages(),
    install_requires=['pyperclip'],
)