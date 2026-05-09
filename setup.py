"""Setup script for PromptScan."""

from setuptools import setup, find_packages

setup(
    name="promptscan",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "promptscan": ["../payloads/*.txt"],
    },
)
