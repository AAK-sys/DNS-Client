import dns.resolver
import binascii

domain = 'www.gmu.edu'
response = dns.resolver.query(domain, 'A', raise_on_no_answer=False)

if response.rrset is not None:
    # Obtain the raw response as bytes
    raw_response = response.response.to_wire()

    # Convert the raw response bytes to hex values
    hex_response = binascii.hexlify(raw_response)

    # Print the hex values
    print(hex_response)
else:
    print(f"No records found for {domain}")


