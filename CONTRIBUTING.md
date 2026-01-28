# Contributing

Thanks for your interest in contributing to Windows Memory Forensics MCP!

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/0xhackerfren/windows-memory-forensics-mcp.git
   cd windows-memory-forensics-mcp
   ```

2. **Create a virtual environment**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**
   ```powershell
   # Install all dependencies including dev tools
   pip install -e ".[all,dev]"
   ```

4. **Verify installation**
   ```powershell
   python verify_setup.py
   ```

## Code Style

This project uses the following tools for code quality:

- **[Black](https://black.readthedocs.io/)** - Code formatting (line length: 100)
- **[Ruff](https://docs.astral.sh/ruff/)** - Linting

Before submitting a PR, format your code:

```powershell
black src/ examples/
ruff check src/ examples/
```

### Style Guidelines

- Use type hints for function parameters and return values
- Write docstrings for public functions and classes
- Keep functions focused and reasonably sized
- Handle errors explicitly with specific exception types (avoid bare `except:`)
- Use ASCII-only characters in log output (Windows console compatibility)

## Testing

Run tests with pytest:

```powershell
pytest
```

When possible, test your changes with a real memory dump. Be careful not to commit any memory dumps or sensitive data.

## Pull Request Guidelines

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make focused changes** - Keep PRs small and focused on a single feature or fix

3. **Write clear commit messages**
   - Use present tense ("Add feature" not "Added feature")
   - Keep the first line under 72 characters
   - Reference issues when applicable (e.g., "Fix #123")

4. **Update documentation** - If your change affects usage, update README.md or docstrings

5. **Test your changes** - Verify the MCP server starts and tools work correctly

6. **Submit the PR** with:
   - Clear description of what changed
   - Why the change was needed
   - How to test it

## Reporting Issues

Open an issue on GitHub with:

- **What you were trying to do** - Steps to reproduce
- **What happened instead** - Error messages, unexpected behavior
- **Environment details** - Python version, OS, backend versions
- **Memory dump info** (if relevant) - Windows version, size (not the dump itself!)

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines. Do not open a public issue for security vulnerabilities.

## Adding New Tools

When adding a new MCP tool:

1. Add the implementation method to `MemoryForensicsMCP` class
2. Add the tool definition to both `get_tools_list()` and `get_tools()` functions
3. Add handling in the `handle_call_tool()` function
4. Update the tool count in README.md and AGENT_RULES.md
5. Add documentation to AGENT_RULES.md tool tables
6. Consider adding an example in the `examples/` directory

## Questions?

Open an issue with your question or start a discussion.
