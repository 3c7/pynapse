from setuptools import setup, find_packages

with open('README.md') as f:
    long_description = f.read()

setup(
    name='pynapse',
    version='0.0.1',
    description='Pynapse - a naive Synpase HTTP API client',
    long_description=long_description,
    url='https://github.com/3c7/pynapse',
    author='Nils Kuhnert',
    license='MIT',
    classifiers=[
        'Development Status :: 1 - Planning',
        'Environment :: Console'
    ],
    keywords='threat intelligence vertex synapse cortex',
    packages=find_packages(),
    install_requires=[
        'requests', 'pymisp'
    ],
    # Todo
    entry_points={}
)
