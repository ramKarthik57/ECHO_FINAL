# Contributing to ECHO

Thank you for your interest in contributing to **ECHO - Encrypted Communication Heuristic Observer**! This document provides guidelines for contributing to this project.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Reporting Issues](#reporting-issues)

---

## Code of Conduct

This project adheres to responsible, ethical use of network analysis tools. All contributors must:

- Use the tool only for lawful purposes
- Respect user privacy — ECHO does not decrypt content, and neither should any contributions
- Be respectful and professional in all communications

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ECHO_FINAL.git
   cd ECHO_FINAL
   ```
3. **Add the upstream remote:**
   ```bash
   git remote add upstream https://github.com/ramKarthik57/ECHO_FINAL.git
   ```

---

## Development Setup

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-asyncio httpx black isort mypy

# Run the test suite to verify setup
pytest tests/ -v
```

---

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/ramKarthik57/ECHO_FINAL/issues) first
2. Create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version)

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and its use case
3. Discuss before implementing to avoid wasted effort

### Submitting Code

1. Create a branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```
2. Make your changes
3. Add/update tests
4. Run the test suite
5. Submit a Pull Request

---

## Pull Request Process

1. **Update documentation** if your changes affect user-facing behavior
2. **Add tests** for new functionality
3. **Ensure all tests pass**: `pytest tests/ -v`
4. **Format your code**: `black . && isort .`
5. **Fill out the PR template** completely
6. **Link any related issues** in the PR description
7. Request review from a maintainer

### PR Title Format

```
[type]: brief description

Types: feat, fix, docs, test, refactor, perf, chore
```

Examples:
- `feat: add PCAP export functionality`
- `fix: correct burst threshold calculation`
- `docs: update API reference for /analyze endpoint`

---

## Coding Standards

### Python Style

- Follow **PEP 8**
- Use **type hints** for all function signatures
- Write **docstrings** for all public functions and classes
- Maximum line length: **100 characters**

```python
def detect_bursts(
    packets: list[dict],
    threshold: float = 2.0
) -> list[dict]:
    """
    Detect traffic bursts in a packet sequence.

    Args:
        packets: List of packet dictionaries with 'timestamp' keys.
        threshold: Time gap (seconds) that defines a burst boundary.

    Returns:
        List of burst dictionaries with 'start', 'end', and 'count' keys.
    """
    ...
```

### Formatting

```bash
# Format code
black . --line-length 100

# Sort imports
isort . --profile black

# Type check
mypy backend/ utils/ --ignore-missing-imports
```

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):
```
feat(burst-analyzer): add sliding window burst detection
fix(flow-builder): handle bidirectional flow deduplication
docs(readme): add Windows Npcap installation note
```

---

## Testing

### Running Tests

```bash
# All tests
pytest tests/ -v

# Specific module
pytest tests/test_burst_analyzer.py -v

# With coverage report
pytest tests/ --cov=backend --cov-report=html
open htmlcov/index.html
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files `test_<module>.py`
- Name test functions `test_<function>_<scenario>`
- Use fixtures for common setup

```python
import pytest
from backend.burst_analyzer import BurstAnalyzer

@pytest.fixture
def analyzer():
    return BurstAnalyzer()

@pytest.fixture
def sample_packets():
    return [
        {"timestamp": 1000.0, "src_ip": "192.168.1.1", "dst_ip": "10.0.0.1"},
        {"timestamp": 1000.5, "src_ip": "192.168.1.1", "dst_ip": "10.0.0.1"},
        {"timestamp": 1005.0, "src_ip": "192.168.1.1", "dst_ip": "10.0.0.1"},
    ]

def test_detect_bursts_identifies_gap(analyzer, sample_packets):
    bursts = analyzer.detect_bursts(sample_packets, threshold=2.0)
    assert len(bursts) == 2  # Two bursts separated by 4.5-second gap
```

---

## Reporting Issues

When reporting security vulnerabilities, please follow the guidelines in [SECURITY.md](SECURITY.md) and **do NOT create a public issue**.

For general bugs and feature requests, use [GitHub Issues](https://github.com/ramKarthik57/ECHO_FINAL/issues).

---

Thank you for contributing to ECHO! 🔭
