from mitreattack.stix20 import MitreAttackData
import os

def query_mitre_attack(query_type, identifier=None, search_term=None):
    """
    Query the MITRE ATT&CK framework for TTPs, groups, software, or campaigns.
    
    Args:
        query_type (str): Type of query ('ttp', 'group', 'software', 'campaign', 'all')
        identifier (str, optional): Specific ATT&CK ID (e.g., 'T1059', 'G0007') to query
        search_term (str, optional): Text to search in name and description fields
    
    Returns:
        dict: Results containing the queried information
    """
    # Load the ATT&CK STIX data
    stix_file = "enterprise-attack.json"  # Update path if needed
    
    if not os.path.exists(stix_file):
        print("STIX file not found. Please download 'enterprise-attack.json' from MITRE's GitHub.")
        return None
    
    attack_data = MitreAttackData(stix_file)
    results = {}

    # Helper function to format object output
    def format_object(obj):
        return {
            "id": obj.get("id", "N/A"),
            "name": obj.get("name", "N/A"),
            "description": obj.get("description", "N/A"),
            "url": obj.get("external_references", [{}])[0].get("url", "N/A")
        }

    # Helper function for text-based search
    def matches_search_term(obj, term):
        term = term.lower()
        name = obj.get("name", "").lower()
        desc = obj.get("description", "").lower()
        return term in name or term in desc

    # Query TTPs (Techniques)
    if query_type in ['ttp', 'all']:
        if identifier:
            techniques = attack_data.get_techniques(identifier)
            if techniques:
                results["techniques"] = format_object(techniques[0])
            else:
                results["techniques"] = f"No technique found for ID: {identifier}"
        elif search_term:
            techniques = attack_data.get_techniques()
            matching_techniques = [t for t in techniques if matches_search_term(t, search_term)]
            results["techniques"] = [format_object(t) for t in matching_techniques[:5]]  # Limit to 5
            if not matching_techniques:
                results["techniques"] = f"No techniques found matching '{search_term}'"
        else:
            techniques = attack_data.get_techniques()
            results["techniques"] = [format_object(t) for t in techniques[:5]]  # Limit to 5

    # Query Groups (Threat Actors)
    if query_type in ['group', 'all']:
        if identifier:
            groups = attack_data.get_group(identifier)
            if groups:
                results["group"] = format_object(groups[0])
            else:
                results["group"] = f"No group found for ID: {identifier}"
        elif search_term:
            groups = attack_data.get_groups()
            matching_groups = [g for g in groups if matches_search_term(g, search_term)]
            results["groups"] = [format_object(g) for g in matching_groups[:5]]  # Limit to 5
            if not matching_groups:
                results["groups"] = f"No groups found matching '{search_term}'"
        else:
            groups = attack_data.get_groups()
            results["groups"] = [format_object(g) for g in groups[:5]]  # Limit to 5

    # Query Software (Tools and Malware)
    if query_type in ['software', 'all']:
        if identifier:
            software = attack_data.get_software(identifier)
            if software:
                results["software"] = format_object(software[0])
            else:
                results["software"] = f"No software found for ID: {identifier}"
        elif search_term:
            software = attack_data.get_software()
            matching_software = [s for s in software if matches_search_term(s, search_term)]
            results["software"] = [format_object(s) for s in matching_software[:5]]  # Limit to 5
            if not matching_software:
                results["software"] = f"No software found matching '{search_term}'"
        else:
            software = attack_data.get_software()
            results["software"] = [format_object(s) for s in software[:5]]  # Limit to 5

    # Query Campaigns
    if query_type in ['campaign', 'all']:
        if identifier:
            campaigns = attack_data.get_campaign(identifier)
            if campaigns:
                results["campaign"] = format_object(campaigns[0])
            else:
                results["campaign"] = f"No campaign found for ID: {identifier}"
        elif search_term:
            campaigns = attack_data.get_campaigns()
            matching_campaigns = [c for c in campaigns if matches_search_term(c, search_term)]
            results["campaigns"] = [format_object(c) for c in matching_campaigns[:5]]  # Limit to 5
            if not matching_campaigns:
                results["campaigns"] = f"No campaigns found matching '{search_term}'"
        else:
            campaigns = attack_data.get_campaigns()
            results["campaigns"] = [format_object(c) for c in campaigns[:5]]  # Limit to 5

    return results

def main():    
    data_result = query_mitre_attack("ttp", "T1059")
    print(data_result)

if __name__ == "__main__":
    main()