from setuptools import setup

setup(
    name="mdtsdb",
    version="3.1",
    description="Python client for TimeEngine",
    author="",
    author_email="",
    install_requires=[
        "requests>=2.23.0",
        "decorator",
        "pika",
        "six",
        "websocket-client",
        "kafka-python",
        "bson",
        "prompt_toolkit"
    ],
    packages=[
        "mdtsdb",
    ],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        "Development Status :: 5 - Production/Stable",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
