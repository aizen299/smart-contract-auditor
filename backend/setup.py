from setuptools import setup, find_packages
from pathlib import Path

long_description = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="chainaudit",
    version="1.1.0",
    description="Smart contract security scanner — Slither + ML exploitability prediction",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Aditya Raina",
    author_email="rainaaditya58@gmail.com",
    url="https://github.com/aizen299/smart-contract-auditor",
    python_requires=">=3.11",
    packages=find_packages(exclude=["tests*", "dist*", "build*", "*.egg-info"]),
    py_modules=["chainaudit_entry"],
    install_requires=[
    "rich",
    "scikit-learn>=1.4.0",
    "pandas>=2.0.0",
    "numpy>=1.24.0",
    "joblib>=1.3.0",
],
    entry_points={
        "console_scripts": [
            "chainaudit=chainaudit_entry:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    license="MIT",
    keywords="solidity smart-contract security audit slither ethereum arbitrum optimism",
    project_urls={
        "Live": "https://chainaudit.vercel.app",
        "Source": "https://github.com/aizen299/smart-contract-auditor",
    },
)