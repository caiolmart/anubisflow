import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="anubisflow",
    version="0.0.1",
    description="A package to extract features for DDoS attacks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/caiolmart/anubisflow",
    packages=setuptools.find_packages()
)