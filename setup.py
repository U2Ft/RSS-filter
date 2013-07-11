import os
from setuptools import setup

setup(
    name="RSS-filter",
    version="2.0.0",
    description="Marks-as-read Feedbin feed items that match a specified filter.",
    long_description=open(os.path.join(os.path.dirname(__file__), 'README.rst')).read(),
    url="https://github.com/U2Ft/RSS-filter",
    license="MIT",
    package_dir={"": "src"},
    py_modules=["RSS_filter"],
    install_requires=["requests>=1.0.0", "configobj", "appdirs", "docopt", "demjson"],
    zip_safe=True,
    entry_points={"console_scripts": ["RSS-filter = RSS_filter:main"]}
)
