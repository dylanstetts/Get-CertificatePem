# Get-CertificatePem.ps1

A PowerShell script to retrieve the PEM-encoded X.509 certificate (and optionally the full chain) from a remote TLS/SSL server. Supports both PowerShell 5.1 and 7+, and works with any .NET version.

## Features

- Fetches the leaf certificate from a remote HTTPS/TLS endpoint.
- Optionally includes the full certificate chain and root certificate.
- Outputs PEM format to the console or writes to a file.
- Supports custom ports and connection timeouts.
- Works with both URL and direct host/port input.

## Usage

```powershell
# Basic usage with a URL
.\Get-CertificatePem.ps1 -Url "https://example.com"

# Specify host and port directly
.\Get-CertificatePem.ps1 -ServerHost "example.com" -Port 8443

# Include the full chain (intermediates)
.\Get-CertificatePem.ps1 -Url "https://example.com" -IncludeChain

# Include the root certificate as well
.\Get-CertificatePem.ps1 -Url "https://example.com" -IncludeChain -IncludeRoot

# Write the PEM(s) to a file
.\Get-CertificatePem.ps1 -Url "https://example.com" -IncludeChain -OutFile "C:\temp\certs\example.pem"
```

## Parameters

- `-Url <string>`: The HTTPS URL to connect to (e.g., `https://contoso.com`).
- `-ServerHost <string>`: The server hostname (alternative to `-Url`).
- `-Port <int>`: The port to connect to (default: 443).
- `-IncludeChain`: Include the full certificate chain (intermediates).
- `-IncludeRoot`: Also include the root certificate (only with `-IncludeChain`).
- `-OutFile <string>`: Write the PEM(s) to a file.
- `-TimeoutSeconds <int>`: Connection timeout in seconds (default: 10).

## Example

```powershell
# Retrieve the Microsoft Graph API certificate chain and save to file
.\Get-CertificatePem.ps1 "https://graph.microsoft.com" -IncludeChain -IncludeRoot -OutFile "C:\temp\graph.pem" -Verbose
```

## Requirements

- PowerShell 5.1 or later (Windows, Linux, macOS)
- Internet access to the target server

## Notes

- The script does not validate the certificate; it retrieves it regardless of trust.
- PEM output is compatible with most tools and platforms.

## License

MIT License

---

*Author: [Your Name
