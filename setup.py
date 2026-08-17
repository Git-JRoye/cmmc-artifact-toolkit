"""
CMMC Artifact Toolkit
Evidence collection and CMMC/NIST SP 800-171 compliance scoring for
Windows, Active Directory, Entra ID, and Intune environments.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cmmc-gatherer",
    version="0.9.0",  # keep in sync with src/cmmc_gatherer/__init__.py:__version__
    author="Tenguard Security",
    description="Evidence collection and CMMC/NIST SP 800-171 compliance scoring for Windows, Active Directory, Entra ID, and Intune environments",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Git-JRoye/cmmc-artifact-toolkit",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.10",
    install_requires=[
        "pywin32>=300",
        "ldap3>=2.9.1",
        "msal>=1.24.0",
        "requests>=2.31.0",
        "pyyaml>=6.0",
    ],
    # No console_scripts entry point: cli.py/gatherer.py (CMMCGatherer.collect_all())
    # are pre-fork upstream code — a single on-prem-only collection path with no
    # tenant config, no cloud plane, no orchestrator, no secret resolution, and no
    # asset scope. Nobody runs this tool that way today; the real entry points are
    # run_assessment.py (YAML-configured, multi-tenant) and pilot_test.py (single
    # hardcoded pilot profile). Shipping a `cmmc-gatherer` command pointed at dead
    # functionality would be worse than shipping none — see the code review that
    # flagged this for the disposition call on cli.py/gatherer.py themselves
    # (rewrite to wrap TenantOrchestrator, or delete outright).
)
