from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_desc = f.read()

setup(
    name="promptstrike",
    version="1.0.0",
    author="Muhammad Abid",
    author_email="v3n0msh3ll@protonmail.com",
    description="AI prompt injection testing framework",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    url="https://github.com/V3n0mSh3ll/promptstrike",
    packages=find_packages(),
    include_package_data=True,
    package_data={"": ["payloads/*.json"]},
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "colorama>=0.4.6",
    ],
    extras_require={
        "proxy": ["pysocks>=1.7.1"],
    },
    entry_points={
        "console_scripts": [
            "promptstrike=promptstrike:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    keywords="ai security prompt-injection llm pentesting red-team",
)
