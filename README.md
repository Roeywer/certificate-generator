# Certificate Generation Script - User Guide

## Overview

This guide provides complete usage instructions and examples for the certificate generation scripts. Choose between the basic interactive script or the advanced script with command-line options.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Root CA Generation](#root-ca-generation)
3. [Basic Script Usage](#basic-script-usage)
4. [Advanced Script Usage](#advanced-script-usage)
5. [Interactive Mode Examples](#interactive-mode-examples)
6. [Command-Line Examples](#command-line-examples)
7. [Batch Processing Examples](#batch-processing-examples)
8. [Troubleshooting](#troubleshooting)

## Quick Start

### Prerequisites
- OpenSSL installed on your system
- CA certificate and private key files (or let the script generate them for you!)
- Bash shell (Linux, macOS, or WSL on Windows)

### Make Scripts Executable
```bash
chmod +x generate-certificate-v1.sh.sh
```

## Root CA Generation

The script now includes **automatic root CA generation** capability, making it a complete one-stop solution for certificate management. You no longer need existing CA files to get started!

### Automatic CA Generation

When you run the script without existing CA files, it will automatically detect this and offer to generate a root CA certificate and key for you:

```bash
./generate-certificate-v1.sh
```

**Example flow:**
```
[INFO] === Certificate Generation Script v2.0 ===

Enter path to CA certificate file: ca.crt
[WARNING] CA certificate file not found: ca.crt
Would you like to generate a root CA certificate? (y/n): y
[INFO] === Root CA Generation ===

Enter CA Organization (O): My Company
Enter CA Organizational Unit (OU): IT Department
Enter CA City/Locality (L): New York
Enter CA State/Province (ST): NY
Enter CA Country Code (C) - 2 letters: US
[INFO] Generating root CA private key (4096 bits)...
[INFO] Generating root CA certificate...
[SUCCESS] Root CA generated successfully!

CA certificate details:
    Subject: C=US, ST=NY, L=New York, O=My Company, OU=IT Department, CN=Root CA
    Issuer: C=US, ST=NY, L=New York, O=My Company, OU=IT Department, CN=Root CA
    Not Before: Jan 15 10:30:00 2024 GMT
    Not After: Jan 15 10:30:00 2034 GMT

CA files created:
  CA Private Key: ca.key
  CA Certificate: ca.crt

[SUCCESS] Root CA generation completed successfully!
```

### Force CA Generation Mode

Use the `--generate-ca` flag to force CA generation mode:

```bash
./generate-certificate-v1.sh --generate-ca --cn "My Root CA" --org "My Company"
```

### CA Generation Options

- `--generate-ca` - Force CA generation mode
- `--ca-days DAYS` - CA validity period (default: 3650 days = 10 years)
- `--ca-key-size SIZE` - CA key size (default: 4096 bits)

**Examples:**
```bash
# Generate CA with custom validity period
./generate-certificate-v1.sh --generate-ca --ca-days 7300 --cn "Long-lived CA"

# Generate CA with custom key size
./generate-certificate-v1.sh --generate-ca --ca-key-size 8192 --cn "High-security CA"

# Complete flow: Generate CA then create certificate
./generate-certificate-v1.sh --generate-ca --cn "My Root CA" --org "My Company" --cn "example.com" --san "example.com,*.example.com"
```

### CA Security Features

The generated root CA includes:
- **4096-bit RSA key** (configurable)
- **10-year validity** (configurable)
- **Proper CA constraints** (CA:TRUE)
- **Key usage** (keyCertSign, cRLSign)
- **Secure file permissions** (600 for key, 644 for cert)
- **Self-signed certificate** (no external dependencies)

## Basic Script Usage

### Interactive Mode (Recommended for beginners)
```bash
./generate-certificate-v1.sh.sh
```

**What you'll be asked:**
1. CA certificate file path
2. CA private key file path
3. Certificate details (CN, Organization, etc.)
4. Subject Alternative Names (SANs)
5. Output file names

**Example session:**
```
[INFO] === Certificate Generation Script ===

Enter path to CA certificate file: /path/to/ca.crt
Enter path to CA private key file: /path/to/ca.key
[INFO] === Certificate Details ===
Enter Common Name (CN): example.com
Enter Organization (O): My Company
Enter Organizational Unit (OU): IT Department
Enter City/Locality (L): New York
Enter State/Province (ST): NY
Enter Country Code (C) - 2 letters: US
Enter certificate validity in days (default: 365): 730
[INFO] === Output Files ===
Enter output certificate key filename (default: certificate.key): 
Enter output certificate filename (default: certificate.crt): 
[SUCCESS] Certificate generated successfully!
```

## Advanced Script Usage

### Interactive Mode
```bash
./generate-certificate-v1.sh
```

### Command-Line Mode
```bash
./generate-certificate-v1.sh [OPTIONS]
```

### Show Help
```bash
./generate-certificate-v1.sh --help
```

### Show Version
```bash
./generate-certificate-v1.sh --version
```

## Interactive Mode Examples

### Example 1: Basic Certificate
```bash
./generate-certificate-v1.sh
```

**Input:**
```
Enter path to CA certificate file: /etc/ssl/ca.crt
Enter path to CA private key file: /etc/ssl/ca.key
Enter Common Name (CN): api.example.com
Enter Organization (O): Example Corp
Enter Organizational Unit (OU): IT Department
Enter City/Locality (L): San Francisco
Enter State/Province (ST): CA
Enter Country Code (C) - 2 letters: US
Enter certificate validity in days (default: 365): 365
Enter key size in bits (default: 2048): 2048
Enter SAN (DNS name, IP address, or email): api.example.com
Add another SAN? (y/n): y
Enter SAN (DNS name, IP address, or email): *.api.example.com
Add another SAN? (y/n): n
Enter output certificate key filename (default: certificate.key): api.key
Enter output certificate filename (default: certificate.crt): api.crt
```

**Output:**
```
[SUCCESS] Certificate generated successfully!

Certificate details:
    Subject: C=US, ST=CA, L=San Francisco, O=Example Corp, OU=IT Department, CN=api.example.com
    Issuer: C=US, ST=CA, L=San Francisco, O=Example Corp, OU=IT Department, CN=Root CA
    Not Before: Jan 15 10:30:00 2024 GMT
    Not After: Jan 15 10:30:00 2025 GMT
    DNS:api.example.com, DNS:*.api.example.com

Files created:
  Certificate Key: api.key
  Certificate: api.crt
```

### Example 2: Multi-Domain Certificate
```bash
./generate-certificate-v1.sh
```

**SAN Input:**
```
Enter SAN (DNS name, IP address, or email): example.com
Add another SAN? (y/n): y
Enter SAN (DNS name, IP address, or email): *.example.com
Add another SAN? (y/n): y
Enter SAN (DNS name, IP address, or email): www.example.com
Add another SAN? (y/n): y
Enter SAN (DNS name, IP address, or email): 192.168.1.100
Add another SAN? (y/n): y
Enter SAN (DNS name, IP address, or email): admin@example.com
Add another SAN? (y/n): n
```

## Command-Line Examples

### Example 1: Basic Certificate
```bash
./generate-certificate-v1.sh \
  --ca-cert /etc/ssl/ca.crt \
  --ca-key /etc/ssl/ca.key \
  --cn example.com \
  --org "Example Corp" \
  --ou "IT Department" \
  --city "San Francisco" \
  --state "CA" \
  --country "US"
```

### Example 2: Certificate with SANs
```bash
./generate-certificate-v1.sh \
  --ca-cert /etc/ssl/ca.crt \
  --ca-key /etc/ssl/ca.key \
  --cn example.com \
  --org "Example Corp" \
  --country "US" \
  --san "example.com,*.example.com,www.example.com,192.168.1.100"
```

### Example 3: High-Security Certificate
```bash
./generate-certificate-v1.sh \
  --ca-cert /etc/ssl/ca.crt \
  --ca-key /etc/ssl/ca.key \
  --cn secure.example.com \
  --org "Secure Corp" \
  --country "US" \
  --days 365 \
  --key-size 4096 \
  --key-file secure.key \
  --cert-file secure.crt \
  --san "secure.example.com,*.secure.example.com"
```

### Example 4: Generate Root CA Only
```bash
./generate-certificate-v1.sh \
  --generate-ca \
  --cn "My Root CA" \
  --org "My Company" \
  --ou "IT Department" \
  --city "New York" \
  --state "NY" \
  --country "US" \
  --ca-days 3650 \
  --ca-key-size 4096
```

### Example 5: Complete One-Stop Solution
```bash
# Generate CA and certificate in one command
./generate-certificate-v1.sh \
  --generate-ca \
  --cn "My Root CA" \
  --org "My Company" \
  --country "US" \
  --cn "example.com" \
  --san "example.com,*.example.com,www.example.com"
```

## Batch Processing Examples

### Example : Multiple Subdomains
```bash
#!/bin/bash
# Generate certificates for multiple subdomains

for subdomain in api app admin portal; do
    echo "Generating certificate for $subdomain.example.com"
    ./generate-certificate-v1.sh \
      --ca-cert /etc/ssl/ca.crt \
      --ca-key /etc/ssl/ca.key \
      --cn "$subdomain.example.com" \
      --org "Example Corp" \
      --country "US" \
      --key-file "$subdomain.key" \
      --cert-file "$subdomain.crt" \
      --san "$subdomain.example.com,*.${subdomain}.example.com"
done
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied
**Error:** `Permission denied: /path/to/ca.key`
**Solution:**
```bash
# Check file permissions
ls -la /path/to/ca.key

# Fix permissions if needed
chmod 600 /path/to/ca.key
```

#### 2. Invalid Private Key
**Error:** `Invalid private key or key is encrypted`
**Solution:**
```bash
# Decrypt the key first
openssl rsa -in encrypted_key.pem -out decrypted_key.pem

# Then use the decrypted key
./generate-certificate-v1.sh --ca-key decrypted_key.pem
```

#### 3. Invalid DNS Name Format
**Error:** `Invalid DNS name format: *.example.com`
**Solution:**
- Use proper domain format: `example.com`, `*.example.com`
- Avoid special characters
- Ensure domain has proper structure

#### 4. File Already Exists
**Error:** `Certificate key file already exists`
**Solution:**
- Choose 'y' to overwrite
- Or specify different filename
- Or remove existing file first

#### 5. OpenSSL Not Found
**Error:** `openssl: command not found`
**Solution:**
```bash
# Install OpenSSL
# Ubuntu/Debian:
sudo apt-get install openssl

# CentOS/RHEL:
sudo yum install openssl

# macOS:
brew install openssl
```

### Validation Examples

#### Valid Inputs
```
✅ DNS Names: example.com, *.example.com, api.example.com
✅ IP Addresses: 192.168.1.1, 10.0.0.1
✅ Email: admin@example.com, user@company.com
✅ Country Codes: US, CA, GB, DE
✅ Key Sizes: 1024, 2048, 4096
✅ Validity Days: 1-3650
```

#### Invalid Inputs
```
❌ DNS Names: example (no domain), .example.com (starts with dot)
❌ IP Addresses: 999.999.999.999, 192.168.1
❌ Email: admin@ (incomplete), @example.com (no user)
❌ Country Codes: USA (too long), us (lowercase)
❌ Key Sizes: 512 (too small), 9999 (too large)
❌ Validity Days: 0 (too small), 9999 (too large)
```

### Debug Mode
```bash
# Run with debug output
bash -x ./generate-certificate-v1.sh

# Check OpenSSL version
openssl version

# Verify CA certificate
openssl x509 -in /path/to/ca.crt -text -noout

# Verify private key
openssl rsa -in /path/to/ca.key -check -noout
```

### File Permissions
```bash
# Set proper permissions for generated files
chmod 600 certificate.key    # Private key - read/write for owner only
chmod 644 certificate.crt     # Certificate - readable by all
chmod 600 ca.key            # CA private key - read/write for owner only
chmod 644 ca.crt            # CA certificate - readable by all
```
