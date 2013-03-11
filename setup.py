from setuptools import setup

setup(
    name="RSS_filter",
    version="0.0.1",
    package_dir={"": "src"},
    py_modules=["RSS_filter"],
    install_requires=["libgreader", "requests>=1.0.0", "configobj", "appdirs", "docopt", "demjson"],
    zip_safe=True,
    entry_points = {"console_scripts": ["RSS-filter = RSS_filter:main"]}
)
