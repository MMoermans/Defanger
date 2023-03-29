def is_ip_address(ip_or_dns: str) -> bool:
    """
    Given a string, determines if it is a valid IP address
    """
    parts = ip_or_dns.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or int(part) > 255:
            return False
    return True


def defang(ip_or_dns: str) -> str:
    """
    Given an IP address or DNS name, defangs it by replacing the last dot with '[.]'
    """
    return ip_or_dns.replace('.', '[.]', ip_or_dns.count('.') - 1)


def refang(ip_or_dns: str) -> str:
    """
    Given a defanged IP address or DNS name, refangs it by replacing '[.]' with '.'
    """
    return ip_or_dns.replace('[.]', '.')


# Prompt user for input
user_input = input("Enter an IP address or DNS name: ")

# Determine whether input needs to be defanged or refanged
if '[.]' in user_input:
    # Input needs to be refanged
    reverted_input = refang(user_input)
    print("Reverted input:", reverted_input)
else:
    # Input needs to be defanged
    if is_ip_address(user_input):
        # Input is an IP address
        defanged_input = defang(user_input)
    else:
        # Input is a DNS name
        defanged_input = defang(user_input)
    print("Defanged input:", defanged_input)
