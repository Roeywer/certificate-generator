#!/bin/bash

# Certificate Generation Script - Best Practices Version
# This script generates a new certificate using an existing CA certificate and key
# Author: Certificate Generation Tool
# Version: 2.0

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script configuration
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="2.0"
readonly DEFAULT_KEY_SIZE=2048
readonly DEFAULT_VALIDITY_DAYS=365
readonly MIN_KEY_SIZE=1024
readonly MAX_VALIDITY_DAYS=3650
readonly DEFAULT_CA_VALIDITY_DAYS=3650  # 10 years for root CA
readonly DEFAULT_CA_KEY_SIZE=4096       # Higher security for CA

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ -n "${temp_dir:-}" && -d "$temp_dir" ]]; then
        log_info "Cleaning up temporary files..."
        rm -rf "$temp_dir"
    fi
    exit $exit_code
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Function to validate file existence and permissions
validate_file() {
    local file_path="$1"
    local file_type="$2"
    local required_perms="${3:-r}"
    
    if [[ ! -e "$file_path" ]]; then
        log_error "$file_type not found at: $file_path"
        return 1
    fi
    
    if [[ ! -f "$file_path" ]]; then
        log_error "$file_type is not a regular file: $file_path"
        return 1
    fi
    
    # Check permissions
    case "$required_perms" in
        "r")
            if [[ ! -r "$file_path" ]]; then
                log_error "$file_type is not readable: $file_path"
                return 1
            fi
            ;;
        "rw")
            if [[ ! -r "$file_path" || ! -w "$file_path" ]]; then
                log_error "$file_type is not readable/writable: $file_path"
                return 1
            fi
            ;;
    esac
    
    return 0
}

# Function to validate private key with better error handling
validate_private_key() {
    local key_path="$1"
    
    if ! openssl rsa -in "$key_path" -check -noout 2>/dev/null; then
        log_error "Invalid private key or key is encrypted: $key_path"
        log_info "If the key is encrypted, please decrypt it first using:"
        log_info "  openssl rsa -in $key_path -out decrypted_key.pem"
        return 1
    fi
    
    return 0
}

# Function to validate certificate
validate_certificate() {
    local cert_path="$1"
    
    if ! openssl x509 -in "$cert_path" -text -noout >/dev/null 2>&1; then
        log_error "Invalid certificate file: $cert_path"
        return 1
    fi
    
    return 0
}

# Function to validate country code
validate_country_code() {
    local country="$1"
    
    if [[ ${#country} -ne 2 ]]; then
        log_error "Country code must be exactly 2 characters (ISO 3166-1 alpha-2)"
        return 1
    fi
    
    # Check if it's alphabetic
    if [[ ! "$country" =~ ^[A-Z]{2}$ ]]; then
        log_error "Country code must be 2 uppercase letters (ISO 3166-1 alpha-2)"
        return 1
    fi
    
    return 0
}

# Function to validate key size
validate_key_size() {
    local key_size="$1"
    
    if ! [[ "$key_size" =~ ^[0-9]+$ ]] || [[ $key_size -lt $MIN_KEY_SIZE ]] || [[ $key_size -gt 8192 ]]; then
        log_error "Key size must be a number between $MIN_KEY_SIZE and 8192"
        return 1
    fi
    
    return 0
}

# Function to validate validity days
validate_validity_days() {
    local days="$1"
    
    if ! [[ "$days" =~ ^[0-9]+$ ]] || [[ $days -lt 1 ]] || [[ $days -gt $MAX_VALIDITY_DAYS ]]; then
        log_error "Validity days must be a number between 1 and $MAX_VALIDITY_DAYS"
        return 1
    fi
    
    return 0
}

# Function to get user input with validation
get_input() {
    local prompt="$1"
    local var_name="$2"
    local validator_func="${3:-}"
    local required="${4:-true}"
    local default_value="${5:-}"
    
    while true; do
        if [[ -n "$default_value" ]]; then
            read -p "$prompt (default: $default_value): " input
        else
            read -p "$prompt: " input
        fi
        
        # Use default if empty and default is provided
        if [[ -z "$input" && -n "$default_value" ]]; then
            input="$default_value"
        fi
        
        if [[ "$required" == "true" && -z "$input" ]]; then
            log_error "This field is required. Please enter a value."
            continue
        fi
        
        if [[ -n "$input" || "$required" == "false" ]]; then
            # Run validator if provided
            if [[ -n "$validator_func" ]]; then
                if "$validator_func" "$input"; then
                    eval "$var_name='$input'"
                    break
                else
                    continue
                fi
            else
                eval "$var_name='$input'"
                break
            fi
        fi
    done
}

# Function to get multiple SAN entries with better validation
get_san_entries() {
    local san_list=()
    local continue_adding="y"
    
    log_info "Enter Subject Alternative Names (SANs). Press Enter with empty input to finish."
    log_info "Examples: example.com, *.example.com, 192.168.1.1, user@example.com"
    
    while [[ "$continue_adding" == "y" || "$continue_adding" == "Y" ]]; do
        read -p "Enter SAN (DNS name, IP address, or email): " san_entry
        
        if [[ -n "$san_entry" ]]; then
            # Validate and determine SAN type
            if [[ "$san_entry" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                # Validate IP address format
                if [[ "$san_entry" =~ ^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
                    san_list+=("IP:$san_entry")
                else
                    log_error "Invalid IP address format: $san_entry"
                    continue
                fi
            elif [[ "$san_entry" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                san_list+=("email:$san_entry")
            else
                # DNS name validation (allows wildcards and subdomains)
                # Basic validation: must contain at least one dot, allow wildcards and hyphens
                if [[ "$san_entry" =~ ^\*?\.?[a-zA-Z0-9.-]+$ ]] && [[ "$san_entry" =~ \. ]]; then
                    san_list+=("DNS:$san_entry")
                else
                    log_error "Invalid DNS name format: $san_entry"
                    log_info "Valid formats: example.com, *.example.com, subdomain.example.com"
                    continue
                fi
            fi
        fi
        
        if [[ ${#san_list[@]} -gt 0 ]]; then
            read -p "Add another SAN? (y/n): " continue_adding
        else
            continue_adding="n"
        fi
    done
    
    # Return the array
    if [[ ${#san_list[@]} -gt 0 ]]; then
        printf '%s\n' "${san_list[@]}"
    else
        echo ""
    fi
}

# Function to show script usage
show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Certificate Generation Script v$SCRIPT_VERSION

OPTIONS:
    -h, --help          Show this help message
    -v, --version       Show version information
    --ca-cert PATH      Path to CA certificate file
    --ca-key PATH       Path to CA private key file
    --cn NAME           Common Name for the certificate
    --org ORGANIZATION  Organization name
    --ou UNIT           Organizational Unit
    --city CITY         City/Locality
    --state STATE       State/Province
    --country CODE      Country code (2 letters)
    --days DAYS        Certificate validity in days (default: $DEFAULT_VALIDITY_DAYS)
    --key-size SIZE     Key size in bits (default: $DEFAULT_KEY_SIZE)
    --key-file FILE     Output key filename (default: certificate.key)
    --cert-file FILE    Output certificate filename (default: certificate.crt)
    --san SANS          Comma-separated list of Subject Alternative Names
    --generate-ca       Generate root CA certificate and key (one-stop solution)
    --ca-days DAYS      CA certificate validity in days (default: $DEFAULT_CA_VALIDITY_DAYS)
    --ca-key-size SIZE  CA key size in bits (default: $DEFAULT_CA_KEY_SIZE)

EXAMPLES:
    $SCRIPT_NAME
    $SCRIPT_NAME --ca-cert /path/to/ca.crt --ca-key /path/to/ca.key --cn example.com
    $SCRIPT_NAME --san "example.com,*.example.com,192.168.1.1"
    $SCRIPT_NAME --generate-ca --cn "My Root CA" --org "My Company"
    $SCRIPT_NAME --generate-ca --ca-days 7300 --ca-key-size 4096

EOF
}

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                echo "$SCRIPT_NAME v$SCRIPT_VERSION"
                exit 0
                ;;
            --ca-cert)
                ca_cert_path="$2"
                shift 2
                ;;
            --ca-key)
                ca_key_path="$2"
                shift 2
                ;;
            --cn)
                common_name="$2"
                shift 2
                ;;
            --org)
                organization="$2"
                shift 2
                ;;
            --ou)
                organizational_unit="$2"
                shift 2
                ;;
            --city)
                city="$2"
                shift 2
                ;;
            --state)
                state="$2"
                shift 2
                ;;
            --country)
                country="$2"
                shift 2
                ;;
            --days)
                validity_days="$2"
                shift 2
                ;;
            --key-size)
                key_size="$2"
                shift 2
                ;;
            --key-file)
                cert_key_file="$2"
                shift 2
                ;;
            --cert-file)
                cert_file="$2"
                shift 2
                ;;
            --san)
                # Parse comma-separated SANs
                IFS=',' read -ra san_array <<< "$2"
                for san in "${san_array[@]}"; do
                    san=$(echo "$san" | xargs)  # trim whitespace
                    if [[ -n "$san" ]]; then
                        if [[ "$san" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                            san_entries_array+=("IP:$san")
                        elif [[ "$san" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                            san_entries_array+=("email:$san")
                        else
                            san_entries_array+=("DNS:$san")
                        fi
                    fi
                done
                shift 2
                ;;
            --generate-ca)
                generate_ca_flag="true"
                shift
                ;;
            --ca-days)
                ca_validity_days="$2"
                shift 2
                ;;
            --ca-key-size)
                ca_key_size="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Function to generate root CA certificate and key
generate_root_ca() {
    local ca_cert_path="$1"
    local ca_key_path="$2"
    local ca_common_name="${3:-Root CA}"
    local ca_organization="${4:-}"
    local ca_organizational_unit="${5:-}"
    local ca_city="${6:-}"
    local ca_state="${7:-}"
    local ca_country="${8:-}"
    local ca_validity_days="${9:-$DEFAULT_CA_VALIDITY_DAYS}"
    local ca_key_size="${10:-$DEFAULT_CA_KEY_SIZE}"
    
    log_info "=== Root CA Generation ==="
    echo
    
    # Get CA certificate details if not provided
    if [[ -z "$ca_organization" ]]; then
        get_input "Enter CA Organization (O)" ca_organization
    fi
    
    if [[ -z "$ca_organizational_unit" ]]; then
        get_input "Enter CA Organizational Unit (OU)" ca_organizational_unit
    fi
    
    if [[ -z "$ca_city" ]]; then
        get_input "Enter CA City/Locality (L)" ca_city
    fi
    
    if [[ -z "$ca_state" ]]; then
        get_input "Enter CA State/Province (ST)" ca_state
    fi
    
    if [[ -z "$ca_country" ]]; then
        get_input "Enter CA Country Code (C) - 2 letters" ca_country "validate_country_code"
    else
        validate_country_code "$ca_country" || exit 1
    fi
    
    # Validate CA validity days
    validate_validity_days "$ca_validity_days" || exit 1
    
    # Validate CA key size
    validate_key_size "$ca_key_size" || exit 1
    
    # Check if output files already exist
    if [[ -f "$ca_key_path" ]]; then
        log_warning "CA private key file already exists: $ca_key_path"
        read -p "Overwrite? (y/n): " overwrite_key
        if [[ "$overwrite_key" != "y" && "$overwrite_key" != "Y" ]]; then
            log_error "CA generation cancelled"
            return 1
        fi
    fi
    
    if [[ -f "$ca_cert_path" ]]; then
        log_warning "CA certificate file already exists: $ca_cert_path"
        read -p "Overwrite? (y/n): " overwrite_cert
        if [[ "$overwrite_cert" != "y" && "$overwrite_cert" != "Y" ]]; then
            log_error "CA generation cancelled"
            return 1
        fi
    fi
    
    # Create temporary directory for CA generation
    local temp_dir=$(mktemp -d)
    local ca_config_file="$temp_dir/ca_openssl.conf"
    
    # Create OpenSSL configuration file for CA
    cat > "$ca_config_file" << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C=$ca_country
ST=$ca_state
L=$ca_city
O=$ca_organization
OU=$ca_organizational_unit
CN=$ca_common_name

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
    
    log_info "Generating root CA private key ($ca_key_size bits)..."
    if ! openssl genrsa -out "$ca_key_path" "$ca_key_size"; then
        log_error "Failed to generate CA private key"
        rm -rf "$temp_dir"
        return 1
    fi
    
    log_info "Generating root CA certificate..."
    if ! openssl req -new -x509 -key "$ca_key_path" -out "$ca_cert_path" -days "$ca_validity_days" -config "$ca_config_file" -extensions v3_ca; then
        log_error "Failed to generate CA certificate"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Set secure file permissions
    chmod 600 "$ca_key_path"
    chmod 644 "$ca_cert_path"
    
    # Verify the generated CA certificate
    log_info "Verifying generated CA certificate..."
    if openssl x509 -in "$ca_cert_path" -text -noout > /dev/null 2>&1; then
        log_success "Root CA generated successfully!"
        echo
        log_info "CA certificate details:"
        openssl x509 -in "$ca_cert_path" -text -noout | grep -E "(Subject:|Issuer:|Not Before|Not After)"
        echo
        log_success "CA files created:"
        log_success "  CA Private Key: $ca_key_path"
        log_success "  CA Certificate: $ca_cert_path"
        
        # Show file permissions
        log_info "File permissions:"
        ls -la "$ca_key_path" "$ca_cert_path"
    else
        log_error "Failed to generate valid CA certificate"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Clean up temporary directory
    rm -rf "$temp_dir"
    
    log_success "Root CA generation completed successfully!"
    echo
    return 0
}

# Main script
main() {
    log_info "=== Certificate Generation Script v$SCRIPT_VERSION ==="
    echo
    
    # Initialize variables
    local ca_cert_path=""
    local ca_key_path=""
    local common_name=""
    local organization=""
    local organizational_unit=""
    local city=""
    local state=""
    local country=""
    local validity_days="$DEFAULT_VALIDITY_DAYS"
    local key_size="$DEFAULT_KEY_SIZE"
    local cert_key_file="certificate.key"
    local cert_file="certificate.crt"
    local generate_ca_flag="false"
    local ca_validity_days="$DEFAULT_CA_VALIDITY_DAYS"
    local ca_key_size="$DEFAULT_CA_KEY_SIZE"
    san_entries_array=()
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Handle CA generation or validation
    if [[ "$generate_ca_flag" == "true" ]]; then
        # Force CA generation mode
        if [[ -z "$ca_cert_path" ]]; then
            ca_cert_path="ca.crt"
        fi
        if [[ -z "$ca_key_path" ]]; then
            ca_key_path="ca.key"
        fi
        
        # Set defaults for CA generation if not provided via command line
        if [[ -z "$common_name" ]]; then
            common_name="Root CA"
        fi
        if [[ -z "$organization" ]]; then
            organization="My Company"
        fi
        if [[ -z "$organizational_unit" ]]; then
            organizational_unit="IT Department"
        fi
        if [[ -z "$city" ]]; then
            city="New York"
        fi
        if [[ -z "$state" ]]; then
            state="NY"
        fi
        if [[ -z "$country" ]]; then
            country="US"
        fi
        
        log_info "Generating root CA certificate and key..."
        if ! generate_root_ca "$ca_cert_path" "$ca_key_path" "$common_name" "$organization" "$organizational_unit" "$city" "$state" "$country" "$ca_validity_days" "$ca_key_size"; then
            log_error "Failed to generate root CA"
            exit 1
        fi
        
        log_success "Root CA generation completed successfully!"
        log_info "You can now use the generated CA files to sign certificates:"
        log_info "  CA Certificate: $ca_cert_path"
        log_info "  CA Private Key: $ca_key_path"
        exit 0
    else
        # Get CA certificate path
        if [[ -z "$ca_cert_path" ]]; then
            get_input "Enter path to CA certificate file" ca_cert_path
        fi
        
        # Check if CA certificate exists, offer to generate if not
        if [[ ! -f "$ca_cert_path" ]]; then
            log_warning "CA certificate file not found: $ca_cert_path"
            read -p "Would you like to generate a root CA certificate? (y/n): " generate_ca
            if [[ "$generate_ca" == "y" || "$generate_ca" == "Y" ]]; then
                # Set default CA key path if not provided
                if [[ -z "$ca_key_path" ]]; then
                    ca_key_path="${ca_cert_path%.*}.key"
                fi
                
                log_info "Generating root CA certificate and key..."
                if ! generate_root_ca "$ca_cert_path" "$ca_key_path" "$common_name" "$organization" "$organizational_unit" "$city" "$state" "$country" "$ca_validity_days" "$ca_key_size"; then
                    log_error "Failed to generate root CA"
                    exit 1
                fi
            else
                log_error "CA certificate is required. Exiting."
                exit 1
            fi
        else
            # Validate existing CA certificate
            validate_file "$ca_cert_path" "CA certificate" || exit 1
            validate_certificate "$ca_cert_path" || exit 1
        fi
        
        # Get CA private key path
        if [[ -z "$ca_key_path" ]]; then
            get_input "Enter path to CA private key file" ca_key_path
        fi
        
        # Check if CA key exists, offer to generate if not
        if [[ ! -f "$ca_key_path" ]]; then
            log_warning "CA private key file not found: $ca_key_path"
            read -p "Would you like to generate a root CA certificate and key? (y/n): " generate_ca
            if [[ "$generate_ca" == "y" || "$generate_ca" == "Y" ]]; then
                # Set default CA cert path if not provided
                if [[ -z "$ca_cert_path" ]]; then
                    ca_cert_path="${ca_key_path%.*}.crt"
                fi
                
                log_info "Generating root CA certificate and key..."
                if ! generate_root_ca "$ca_cert_path" "$ca_key_path" "$common_name" "$organization" "$organizational_unit" "$city" "$state" "$country" "$ca_validity_days" "$ca_key_size"; then
                    log_error "Failed to generate root CA"
                    exit 1
                fi
            else
                log_error "CA private key is required. Exiting."
                exit 1
            fi
        else
            # Validate existing CA private key
            validate_file "$ca_key_path" "CA private key" || exit 1
            validate_private_key "$ca_key_path" || exit 1
        fi
    fi
    
    # Get certificate details
    echo
    log_info "=== Certificate Details ==="
    
    if [[ -z "$common_name" ]]; then
        get_input "Enter Common Name (CN)" common_name
    fi
    
    if [[ -z "$organization" ]]; then
        get_input "Enter Organization (O)" organization
    fi
    
    if [[ -z "$organizational_unit" ]]; then
        get_input "Enter Organizational Unit (OU)" organizational_unit
    fi
    
    if [[ -z "$city" ]]; then
        get_input "Enter City/Locality (L)" city
    fi
    
    if [[ -z "$state" ]]; then
        get_input "Enter State/Province (ST)" state
    fi
    
    if [[ -z "$country" ]]; then
        get_input "Enter Country Code (C) - 2 letters" country "validate_country_code"
    else
        validate_country_code "$country" || exit 1
    fi
    
    # Get certificate validity period
    if [[ "$validity_days" == "$DEFAULT_VALIDITY_DAYS" ]]; then
        get_input "Enter certificate validity in days" validity_days "validate_validity_days" "false" "$DEFAULT_VALIDITY_DAYS"
    else
        validate_validity_days "$validity_days" || exit 1
    fi
    
    # Get key size
    if [[ "$key_size" == "$DEFAULT_KEY_SIZE" ]]; then
        get_input "Enter key size in bits" key_size "validate_key_size" "false" "$DEFAULT_KEY_SIZE"
    else
        validate_key_size "$key_size" || exit 1
    fi
    
    # Get Subject Alternative Names
    if [[ ${#san_entries_array[@]} -eq 0 ]]; then
        echo
        while IFS= read -r line; do
            [[ -n "$line" ]] && san_entries_array+=("$line")
        done < <(get_san_entries)
    fi
    
    # Get output file names
    echo
    log_info "=== Output Files ==="
    get_input "Enter output certificate key filename" cert_key_file "" "false" "$cert_key_file"
    get_input "Enter output certificate filename" cert_file "" "false" "$cert_file"
    
    # Check if output files already exist
    if [[ -f "$cert_key_file" ]]; then
        log_warning "Certificate key file already exists: $cert_key_file"
        read -p "Overwrite? (y/n): " overwrite_key
        if [[ "$overwrite_key" != "y" && "$overwrite_key" != "Y" ]]; then
            log_error "Operation cancelled"
            exit 1
        fi
    fi
    
    if [[ -f "$cert_file" ]]; then
        log_warning "Certificate file already exists: $cert_file"
        read -p "Overwrite? (y/n): " overwrite_cert
        if [[ "$overwrite_cert" != "y" && "$overwrite_cert" != "Y" ]]; then
            log_error "Operation cancelled"
            exit 1
        fi
    fi
    
    # Create temporary directory for CSR
    temp_dir=$(mktemp -d)
    local csr_file="$temp_dir/certificate.csr"
    local config_file="$temp_dir/openssl.conf"
    
    # Create OpenSSL configuration file
    cat > "$config_file" << EOF
[req]
default_bits = $key_size
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
C=$country
ST=$state
L=$city
O=$organization
OU=$organizational_unit
CN=$common_name

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
EOF

    # Add SAN extension if SAN entries were provided
    if [[ ${#san_entries_array[@]} -gt 0 ]]; then
        # Add alt_names section to the config file
        cat >> "$config_file" << EOF

[alt_names]
EOF
        
        # Add each SAN entry with proper numbering
        dns_count=1
        ip_count=1
        email_count=1
        
        for san_entry in "${san_entries_array[@]}"; do
            if [[ "$san_entry" =~ ^DNS: ]]; then
                echo "DNS.$dns_count = ${san_entry#DNS:}" >> "$config_file"
                ((dns_count++))
            elif [[ "$san_entry" =~ ^IP: ]]; then
                echo "IP.$ip_count = ${san_entry#IP:}" >> "$config_file"
                ((ip_count++))
            elif [[ "$san_entry" =~ ^email: ]]; then
                echo "email.$email_count = ${san_entry#email:}" >> "$config_file"
                ((email_count++))
            fi
        done
        
        # Update the v3_req section to reference alt_names
        sed -i '' 's/^keyUsage = nonRepudiation, digitalSignature, keyEncipherment$/keyUsage = nonRepudiation, digitalSignature, keyEncipherment\nsubjectAltName = @alt_names/' "$config_file"
    fi
    
    log_info "Generating certificate key ($key_size bits)..."
    if ! openssl genrsa -out "$cert_key_file" "$key_size"; then
        log_error "Failed to generate private key"
        exit 1
    fi
    
    log_info "Generating Certificate Signing Request (CSR)..."
    if ! openssl req -new -key "$cert_key_file" -out "$csr_file" -config "$config_file"; then
        log_error "Failed to generate CSR"
        exit 1
    fi
    
    log_info "Generating certificate using CA..."
    if ! openssl x509 -req -in "$csr_file" -CA "$ca_cert_path" -CAkey "$ca_key_path" -CAcreateserial -out "$cert_file" -days "$validity_days" -extensions v3_req -extfile "$config_file"; then
        log_error "Failed to generate certificate"
        exit 1
    fi
    
    # Verify the generated certificate
    log_info "Verifying generated certificate..."
    if openssl x509 -in "$cert_file" -text -noout > /dev/null 2>&1; then
        log_success "Certificate generated successfully!"
        echo
        log_info "Certificate details:"
        openssl x509 -in "$cert_file" -text -noout | grep -E "(Subject:|Issuer:|Not Before|Not After|DNS:|IP Address:|Email:)"
        echo
        log_success "Files created:"
        log_success "  Certificate Key: $cert_key_file"
        log_success "  Certificate: $cert_file"
        
        # Show file permissions
        log_info "File permissions:"
        ls -la "$cert_key_file" "$cert_file"
    else
        log_error "Failed to generate valid certificate"
        exit 1
    fi
    
    log_success "Certificate generation completed successfully!"
}

# Run main function
main "$@"
