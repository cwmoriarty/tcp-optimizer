"""
Optional py2app build script.

On a Mac, with py2app installed (`pip3 install py2app`), run:

    python3 setup.py py2app

to produce a double-clickable TCP Optimizer.app in dist/.
"""
from setuptools import setup

APP = ["tcp_optimizer.py"]
OPTIONS = {
    "argv_emulation": True,
    "plist": {
        "CFBundleName": "TCP Optimizer",
        "CFBundleDisplayName": "TCP Optimizer",
        "CFBundleIdentifier": "com.punksm4ck.tcpoptimizer",
        "CFBundleShortVersionString": "1.0.0",
        "NSHumanReadableCopyright": "MIT License",
    },
}

setup(
    app=APP,
    name="TCP Optimizer",
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
