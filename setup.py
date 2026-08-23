from setuptools import setup, find_packages

setup(
    name="rushingtech-agents",
    version="2.9.0",
    description="OpenAI-compatible AI agents for solo full-stack operators — security audit, Stripe billing, Railway deploy, code review, and project scaffolding.",
    author="Rushing Technologies",
    author_email="nickrushing@rushingtechnologies.com",
    url="https://rushingtechnologies.com",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "openai>=1.50.0",
        "anthropic>=0.40.0",
        # fleet_policy parses dependabot.yml. Declared rather than optional:
        # an absent parser made the rule report "no findings", which is a
        # silent false-negative in a policy checker — the worst failure mode
        # it has.
        "PyYAML>=6.0",
    ],
    extras_require={
        "dev": ["pytest", "black", "ruff"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries",
        "Topic :: Security",
    ],
)
