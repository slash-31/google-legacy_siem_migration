import re

def parse_customer_info(output: str) -> dict:
    """
    Parses the output of the customer management CLI tool into a dictionary.
    Handles standard key:value pairs, lists (e.g. frontend_paths), and 
    special 'customer_features' long string.
    """
    data = {}
    
    # Pre-processing: split by lines, but handle multi-line values if any 
    # (though sample seems to be mostly single line or clearly delimited)
    lines = output.splitlines()
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Handle key: value pairs
        match = re.match(r"^([^:]+):\s*(.*)$", line)
        if match:
            key = match.group(1).strip()
            value = match.group(2).strip()
            
            # Special handling for arrays like [val1 val2]
            if value.startswith('[') and value.endswith(']'):
                # remove brackets
                content = value[1:-1].strip()
                if content:
                    data[key] = content.split()
                else:
                    data[key] = []
            
            # Special handling for customer_features
            elif key == "customer_features":
                features = {}
                # The sample shows features as space separated key:value
                # e.g. web_app_enabled:true enable_dynamic_parsing_opt_in:true
                # Note: some values might be strings if they don't look like bools, 
                # but sample is mostly bools.
                feature_pairs = value.split()
                for pair in feature_pairs:
                    if ':' in pair:
                        f_key, f_val = pair.split(':', 1)
                        # Skip numeric key:value pairs (e.g. 123:456)
                        if f_key.isdigit() and f_val.isdigit():
                            continue
                        # clean up boolean strings
                        if f_val.lower() == 'true':
                            features[f_key] = True
                        elif f_val.lower() == 'false':
                            features[f_key] = False
                        else:
                            features[f_key] = f_val
                data[key] = features
                
            # Special handling for external_project_info
            elif key == "external_project_info":
                ext_info = {}
                # Format: gcp_project_id:"project-id" bq_dataset_name:"datalake" ...
                # Robust regex for key:"value" or key:value
                pairs = re.findall(r'(\w+):(?:"([^"]*)"|(\S+))', value)
                for k, v_quoted, v_simple in pairs:
                    val = v_quoted if v_quoted else v_simple
                    if val.isdigit():
                        val = int(val)
                    ext_info[k] = val
                data[key] = ext_info

            # Special handling for response_platform_uri (nested key:value)
            # Format: base_uri:"https://example.siemplify-soar.com:443" type:RESPONSE_PLATFORM_TYPE_SIEMPLIFY
            elif key == "response_platform_uri":
                rp_info = {}
                pairs = re.findall(r'(\w+):(?:"([^"]*)"|(\S+))', value)
                for k, v_quoted, v_simple in pairs:
                    rp_info[k] = v_quoted if v_quoted else v_simple
                data[key] = rp_info

            else:
                data[key] = value

    return data

def extract_soar_status(customer_data: dict) -> dict:
    """
    Extract SOAR configuration status from parsed customer info.

    Checks:
    - customer_features.soar_enabled
    - response_platform_uri.base_uri
    - customer_code (lowercased = soar_fe)

    Returns dict with soar_enabled, soar_uri, and suggested soar_fe.
    """
    features = customer_data.get('customer_features', {})
    rp_uri = customer_data.get('response_platform_uri', {})

    soar_enabled = features.get('soar_enabled', False)
    soar_uri = rp_uri.get('base_uri', '') if isinstance(rp_uri, dict) else ''

    # customer_code lowercased = soar_fe
    customer_code = customer_data.get('customer_code', '')
    soar_fe = customer_code.lower() if customer_code else ''

    return {
        'soar_enabled': bool(soar_enabled),
        'soar_uri': soar_uri,
        'soar_fe': soar_fe,
        'customer_code': customer_code,
        'already_configured': bool(soar_enabled and soar_uri)
    }


def check_byop_status(customer_data: dict) -> dict:
    """
    Analyzes parsed customer data to determine BYOP status.
    Returns a dict with 'is_byop' (bool) and 'details' (str).
    """
    features = customer_data.get('customer_features', {})
    ext_info = customer_data.get('external_project_info', {})
    
    # Check 1: Explicit feature flag
    byop_enabled = features.get('byop_enabled', False)
    
    # Check 2: External project ID difference
    # If external gcp_project_id differs from main gcp_project_id, likely BYOP.
    main_project = customer_data.get('gcp_project_id')
    ext_project = ext_info.get('gcp_project_id')
    
    is_byop = byop_enabled or (ext_project and ext_project != main_project)
    
    return {
        'is_byop': bool(is_byop),
        'byop_enabled_flag': byop_enabled,
        'main_project': main_project,
        'external_project': ext_project,
        'details': f"Feature Flag: {byop_enabled}, Ext Project: {ext_project}"
    }
