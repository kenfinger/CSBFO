# Credential Spraying and Brute Force Orchestrator

A sophisticated Python-based tool for conducting controlled credential testing while maintaining operational security and avoiding detection.

## Features

- Adaptive rate limiting and delay mechanisms
- Multi-target attack coordination with progress tracking
- Integration with password policy enforcement detection
- Real-time monitoring of account lockout patterns
- Support for various authentication protocols (SSH, RDP, LDAP, HTTP)
- Type-safe implementation with comprehensive error handling

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Copy `.env.example` to `.env` and configure your settings

## Usage

```bash
python -m credential_orchestrator --targets targets.txt --usernames usernames.txt --passwords passwords.txt --protocol ssh
```

## Security Note

This tool is intended for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

## License

MIT License
