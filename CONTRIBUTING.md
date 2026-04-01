# Contributing to Cloud IDS

Thank you for your interest in improving Cloud IDS! Below you will find a basic guide on how you can actively contribute.

## Workflow

1. **Fork the reporsitory**: Start by creating a personal fork on GitHub.
2. **Clone your fork**: Pull down the repository locally.
   `git clone https://github.com/your-username/cloud-ids.git`
3. **Environment Setup**: Ensure you are using `venv` and installing the `requirements.txt`.
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
4. **Create a branch**: Create an isolated branch `feature/your-feature-name` or `bugfix/issue-it-solves`.
5. **Implement**: Keep your changes modular, type-hinted, and add docstrings to new functions.
6. **Test**: Run the test suite under the `tests/` directory ensuring regressions are not introduced.
   `pytest tests/`
7. **Submit a Pull Request**: Submit your detailed Pull Request back to the main repository.

## Python Standards
- Use **typing hints** (`list[dict]`, `str`, `Any`) universally.
- Ensure all public functions carry a standard docstring describing parameters and return values.
- Respect the existing module architecture: `ingestion`, `features`, `detection`, `claude_analysis`, and `api`.

## Pull Request Process
- Detail the problem your PR solves.
- If introducing UI elements in the React application, attach a screenshot.
- Acknowledge that your contribution will be licensed under the MIT License present in the root.
