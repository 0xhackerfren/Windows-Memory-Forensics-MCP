# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | Yes                |
| < 1.1   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. **Email the maintainer** with details of the vulnerability
3. **Include the following information:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

You can expect:
- Acknowledgment within 48 hours
- Regular updates on the fix progress
- Credit in the security advisory (unless you prefer to remain anonymous)

## Security Best Practices

When using this MCP server for memory forensics:

### Handling Memory Dumps

- **Treat memory dumps as sensitive data** - They may contain passwords, encryption keys, personal data, and other secrets
- **Store dumps securely** - Use encrypted storage and restrict access
- **Do not commit dumps to version control** - The `.gitignore` already excludes common dump extensions
- **Sanitize or destroy dumps** after analysis is complete

### Running the MCP Server

- **Use a dedicated analysis environment** - Consider using a VM or isolated system
- **Keep dependencies updated** - Regularly update Volatility 3, MemProcFS, and other dependencies
- **Review output paths** - Ensure extracted files are written to intended locations
- **Be cautious with untrusted dumps** - Malicious actors could craft memory dumps to exploit analysis tools

### YARA Rules

- **Validate YARA rules before use** - Malformed or resource-intensive rules could cause issues
- **Use trusted rule sources** - Be cautious with rules from unknown sources

### External Tools

- **Keep cdb.exe and dotnet-dump updated** - Use official sources (Windows SDK, .NET SDK)
- **Verify tool integrity** - Ensure debugging tools haven't been tampered with

## Known Security Considerations

1. **Path Handling** - The MCP accepts file paths as input. While paths are validated, always verify output locations.

2. **Subprocess Execution** - The CLR analyzer uses subprocess calls to cdb.exe and dotnet-dump. These are executed with user-provided minidump paths.

3. **Memory Limits** - Large operations have size limits (100MB for reads, 1GB for exports) to prevent resource exhaustion.

4. **No Authentication** - The MCP server itself does not implement authentication. Access control should be handled at the deployment level.
