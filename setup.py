import re

from setuptools import setup

with open("src/monobear/__init__.py", encoding="utf8") as f:
    version = re.search(r'__version__ = "(.*?)"', f.read()).group(1)

requirements = []
with open("requirements.txt", encoding='utf8') as f:
    requirements = f.read().splitlines()

# Metadata goes in setup.cfg. These are here for GitHub's dependency graph.
setup(
    name="monobear-mailcow-addons",
    version=version,
    install_requires=requirements
)
