from setuptools import setup, find_packages

setup(
    name="chainaudit",
    version="0.1.0",
    packages=find_packages(),
    package_data={
        "chainaudit.ml": ["*.joblib"],
        "chainaudit": ["ml/*.joblib"],
    },
    include_package_data=True,
)
