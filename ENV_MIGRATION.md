# Environment Configuration Migration Guide

This guide helps you migrate from YAML-based configuration to the new .env-based configuration system, which provides better security and flexibility for managing Wazuh credentials and OpenAI API keys.

## 🎯 Why Use .env Configuration?

### Benefits
- **Security**: Sensitive credentials are not committed to version control
- **Flexibility**: Easy to change configuration without modifying code
- **Environment-specific**: Different .env files for dev/staging/prod
- **Industry Standard**: Follows 12-factor app methodology
- **IDE Support**: Better syntax highlighting and validation

### Before (.yaml)
```yaml
clusters:
  prod:
    name: prod
    api_url: https://wazuh.company.tld:55000
    username: api-user
    password: S3cr3t!  # ❌ Credentials in version control
    ssl_verify: true
```

### After (.env)
```bash
# ✅ Credentials in environment variables
WAZUH_PROD_URL=https://wazuh.company.tld:55000
WAZUH_PROD_USERNAME=api-user
WAZUH_PROD_PASSWORD=S3cr3t!
WAZUH_PROD_SSL_VERIFY=true
```

## 🚀 Quick Migration

### Option 1: Automatic Conversion
```bash
# Convert existing clusters.yml to .env
python setup_env.py --from-yaml clusters.yml

# Validate the new configuration
python client.py --validate-only
```

### Option 2: Interactive Setup
```bash
# Interactive setup wizard
python setup_env.py --interactive

# Follow the prompts to configure your clusters
```

### Option 3: Manual Setup
```bash
# Copy example and edit
cp .env.example .env
# Edit .env with your actual values

# Validate configuration
python env_config.py
```

## 📝 Configuration Mapping

### YAML to Environment Variables

| YAML Path | Environment Variable | Example |
|-----------|---------------------|---------|
| `clusters.prod.api_url` | `WAZUH_PROD_URL` | `https://wazuh.company.tld:55000` |
| `clusters.prod.username` | `WAZUH_PROD_USERNAME` | `api-user` |
| `clusters.prod.password` | `WAZUH_PROD_PASSWORD` | `S3cr3t!` |
| `clusters.prod.ssl_verify` | `WAZUH_PROD_SSL_VERIFY` | `true` |
| OpenAI API Key | `OPENAI_API_KEY` | `sk-...` |

### Multiple Clusters

**YAML:**
```yaml
clusters:
  prod:
    name: prod
    api_url: https://wazuh-prod:55000
    username: prod-user
    password: prod-pass
  lab:
    name: lab
    api_url: https://wazuh-lab:55000
    username: lab-user
    password: lab-pass
```

**Environment:**
```bash
# Production cluster
WAZUH_PROD_URL=https://wazuh-prod:55000
WAZUH_PROD_USERNAME=prod-user
WAZUH_PROD_PASSWORD=prod-pass

# Lab cluster
WAZUH_LAB_URL=https://wazuh-lab:55000
WAZUH_LAB_USERNAME=lab-user
WAZUH_LAB_PASSWORD=lab-pass
```

## 🔧 Usage Changes

### Before (YAML)
```bash
# Required to specify config file
python client.py --config clusters.yml --openai-key sk-...

# Environment variables mixed with file config
export OPENAI_API_KEY=sk-...
python client.py --config clusters.yml
```

### After (.env)
```bash
# Simple - everything in .env
python client.py

# With validation
python client.py --validate-only

# Custom .env location
python client.py --env-file /path/to/.env

# Still supports YAML as fallback
python client.py --config clusters.yml
```

## 🛡️ Security Best Practices

### 1. Protect Your .env File
```bash
# Set restrictive permissions
chmod 600 .env

# Ensure it's in .gitignore (already configured)
echo ".env" >> .gitignore
```

### 2. Use Different .env Files by Environment
```bash
# Development
cp .env.example .env.dev

# Staging
cp .env.example .env.staging

# Production
cp .env.example .env.prod

# Use specific file
python client.py --env-file .env.prod
```

### 3. Environment-Specific Deployment
```bash
# Docker
docker run -it --env-file .env.prod wazuh-mcp-client

# systemd
Environment=OPENAI_API_KEY=sk-...
Environment=WAZUH_PROD_URL=https://...

# Kubernetes
kubectl create secret generic wazuh-config --from-env-file=.env.prod
```

## 🧪 Testing Your Configuration

### 1. Validate Configuration
```bash
# Test environment loading
python env_config.py

# Validate client configuration
python client.py --validate-only

# Full test suite
python test_client.py
```

### 2. Debug Configuration Issues
```bash
# Enable debug logging
echo "LOG_LEVEL=debug" >> .env

# Check loaded configuration
python -c "
from env_config import get_mcp_config
config = get_mcp_config()
print(f'Clusters: {[c.name for c in config.clusters]}')
print(f'OpenAI Key: {config.openai_api_key[:10]}...')
"
```

## 🔄 Rollback to YAML (if needed)

If you need to rollback to YAML configuration:

```bash
# Create YAML from environment
python -c "
from env_config import get_mcp_config, create_clusters_yaml
config = get_mcp_config()
create_clusters_yaml(config, 'clusters.yml')
print('Created clusters.yml from environment')
"

# Use YAML configuration
python client.py --config clusters.yml --openai-key YOUR_KEY
```

## 📋 Troubleshooting

### Common Issues

**1. "Configuration error: No cluster configurations found"**
```bash
# Check environment variables
env | grep WAZUH_

# Validate .env file exists and has correct format
python env_config.py
```

**2. "OpenAI API key is required"**
```bash
# Check if key is set
echo $OPENAI_API_KEY

# Check .env file
grep OPENAI_API_KEY .env
```

**3. "python-dotenv not available"**
```bash
# Install missing dependency
pip install python-dotenv
```

**4. "Cluster has placeholder URL/username/password"**
```bash
# Edit .env file and replace placeholder values
# Check with validation
python client.py --validate-only
```

### Getting Help

```bash
# Environment setup help
python setup_env.py --help

# Client help
python client.py --help

# Configuration validation
python env_config.py

# Full test
python test_client.py
```

## 🎉 Next Steps

After successful migration:

1. **Delete sensitive YAML files**: Remove or secure any YAML files with credentials
2. **Update documentation**: Update any internal docs or scripts
3. **Test thoroughly**: Run full test suite to ensure everything works
4. **Set up CI/CD**: Configure your deployment pipeline to use .env files
5. **Train your team**: Share this guide with your team members

The new .env configuration system provides a more secure, flexible, and maintainable way to manage your Wazuh MCP client configuration!
