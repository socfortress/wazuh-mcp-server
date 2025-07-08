#!/usr/bin/env python3
"""
Environment setup script for Wazuh MCP Client

This script helps users set up .env configuration and migrate from YAML config.
"""

import sys
from pathlib import Path
import yaml

def create_env_from_yaml(yaml_file: str, env_file: str = ".env") -> bool:
    """Create .env file from existing clusters.yml"""
    try:
        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)
        
        clusters = data.get('clusters', {})
        if not clusters:
            print(f"❌ No clusters found in {yaml_file}")
            return False
        
        env_content = """# Wazuh MCP Server Environment Configuration
# Generated from clusters.yml

# OpenAI Configuration (add your key here)
OPENAI_API_KEY=your-openai-api-key-here

"""
        
        for cluster_name, cluster_data in clusters.items():
            env_content += f"""# {cluster_name.title()} Cluster
WAZUH_{cluster_name.upper()}_URL={cluster_data['api_url']}
WAZUH_{cluster_name.upper()}_USERNAME={cluster_data['username']}
WAZUH_{cluster_name.upper()}_PASSWORD={cluster_data['password']}
WAZUH_{cluster_name.upper()}_SSL_VERIFY={str(cluster_data.get('ssl_verify', True)).lower()}

"""
        
        env_content += """# MCP Server Configuration
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8080
LOG_LEVEL=info

# Tool Filtering (optional)
# WAZUH_DISABLED_TOOLS=DeleteAgentTool,RestartManagerTool
# WAZUH_DISABLED_CATEGORIES=dangerous,write
# WAZUH_READ_ONLY=false
"""
        
        with open(env_file, 'w') as f:
            f.write(env_content)
        
        print(f"✅ Created {env_file} from {yaml_file}")
        print(f"⚠️ Don't forget to set your OpenAI API key in {env_file}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to convert {yaml_file}: {e}")
        return False


def create_example_env(env_file: str = ".env") -> bool:
    """Create an example .env file"""
    try:
        env_content = """# Wazuh MCP Server Environment Configuration
# Copy from .env.example and fill in your actual values

# OpenAI Configuration
OPENAI_API_KEY=your-openai-api-key-here

# Wazuh Manager Configuration
# Production Cluster
WAZUH_PROD_URL=https://wazuh.company.tld:55000
WAZUH_PROD_USERNAME=api-user
WAZUH_PROD_PASSWORD=S3cr3t!
WAZUH_PROD_SSL_VERIFY=true

# Lab/Testing Cluster (optional)
# WAZUH_LAB_URL=https://wazuh-lab.company.tld:55000
# WAZUH_LAB_USERNAME=wazuh
# WAZUH_LAB_PASSWORD=lab123
# WAZUH_LAB_SSL_VERIFY=false

# MCP Server Configuration
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8080
LOG_LEVEL=info

# Tool Filtering (optional)
# WAZUH_DISABLED_TOOLS=DeleteAgentTool,RestartManagerTool
# WAZUH_DISABLED_CATEGORIES=dangerous,write
# WAZUH_READ_ONLY=false
"""
        
        with open(env_file, 'w') as f:
            f.write(env_content)
        
        print(f"✅ Created example {env_file}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to create {env_file}: {e}")
        return False


def validate_env_file(env_file: str = ".env") -> bool:
    """Validate .env file configuration"""
    if not Path(env_file).exists():
        print(f"❌ {env_file} not found")
        return False
    
    # Load environment
    from env_config import get_mcp_config, validate_config
    
    try:
        config = get_mcp_config(env_file)
        issues = validate_config(config)
        
        if issues:
            print(f"⚠️ Issues found in {env_file}:")
            for issue in issues:
                print(f"  - {issue}")
            return False
        else:
            print(f"✅ {env_file} validation passed")
            print(f"Configured clusters: {[c.name for c in config.clusters]}")
            return True
            
    except Exception as e:
        print(f"❌ Error validating {env_file}: {e}")
        return False


def interactive_setup():
    """Interactive setup process"""
    print("🚀 Wazuh MCP Client Environment Setup")
    print("=" * 50)
    
    # Check if .env already exists
    if Path(".env").exists():
        response = input("📄 .env file already exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print("Keeping existing .env file")
            return validate_env_file()
    
    # Check if clusters.yml exists
    yaml_files = list(Path('.').glob('*clusters*.yml'))
    if yaml_files:
        print(f"📄 Found YAML config files: {[str(f) for f in yaml_files]}")
        response = input("Convert from YAML to .env? (y/n): ")
        if response.lower() == 'y':
            yaml_file = yaml_files[0]
            if len(yaml_files) > 1:
                print("Multiple YAML files found:")
                for i, f in enumerate(yaml_files):
                    print(f"  {i+1}. {f}")
                choice = int(input("Select file (number): ")) - 1
                yaml_file = yaml_files[choice]
            
            if create_env_from_yaml(str(yaml_file)):
                print("\n📝 Next steps:")
                print("1. Edit .env file and set your OpenAI API key")
                print("2. Update any placeholder values")
                print("3. Run: python client.py --validate-only")
                return True
    
    # Create example .env
    print("📄 Creating example .env file...")
    if create_example_env():
        print("\n📝 Next steps:")
        print("1. Edit .env file with your actual Wazuh credentials")
        print("2. Set your OpenAI API key")
        print("3. Run: python client.py --validate-only")
        return True
    
    return False


def main():
    """Main setup function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Wazuh MCP Client Environment Setup")
    parser.add_argument("--from-yaml", help="Convert from YAML file to .env")
    parser.add_argument("--validate", action="store_true", help="Validate existing .env file")
    parser.add_argument("--create-example", action="store_true", help="Create example .env file")
    parser.add_argument("--interactive", action="store_true", help="Interactive setup")
    
    args = parser.parse_args()
    
    if args.validate:
        return 0 if validate_env_file() else 1
    
    elif args.from_yaml:
        return 0 if create_env_from_yaml(args.from_yaml) else 1
    
    elif args.create_example:
        return 0 if create_example_env() else 1
    
    elif args.interactive:
        return 0 if interactive_setup() else 1
    
    else:
        # Default: interactive setup
        return 0 if interactive_setup() else 1


if __name__ == "__main__":
    sys.exit(main())
