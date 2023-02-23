import socket

# get response from url
def get_response(URL):

    return ""

#parse the dns server response
def parse_response(hexastring):
    # gmu.edu response example. Some websites have multiple IP addresses that the dns resolves hence multiple hexadecimal responses or a longer hexadecimal. How this will affect the parsing is still unkonwn.
    hexastring = "9aa38580000100010000000003676d75036564750000010001c00c0001000100000e10000481ae861c"


url = "gmu.edu"
parse_response(get_response(url))


