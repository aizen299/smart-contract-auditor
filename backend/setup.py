from setuptools import setup
from pathlib import Path

setup(
    name="chainaudit",
    version="1.0.0",
    description="ChainAudit — Smart contract security scanner CLI",
    author="ChainAudit",
    python_requires=">=3.11",
    package_dir={"": "."},
    packages=["src", "ml"],
    py_modules=["chainaudit_entry"],
    install_requires=[
        "fastapi",
        "uvicorn",
        "python-multipart",
        "rich",
        "slither-analyzer",
        "scikit-learn==1.4.0",
        "pandas==2.2.0",
        "numpy==1.26.4",
        "joblib==1.3.2",
    ],
    entry_points={
        "console_scripts": [
            "chainaudit=chainaudit_entry:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
)