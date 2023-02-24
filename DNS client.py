import socket

# get response from url
def get_response(URL):

    return ""

#parse the dns server response
def parse_response(hexastring):
    # gmu.edu response example. Some websites have multiple IP addresses that the dns resolves hence multiple 
    # hexadecimal responses or a longer hexadecimal. How this will affect the parsing is still unknown.
    hexastring = b's\x05\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03gmu\x03edu\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x02{\x00\x04\x81\xae\x86\x1c'
    
    # If standard response, process Header, Question, & Answer

    # Processing header
    header_bytes = []
    for i in range(12):
        header_bytes.append(hexastring[i])
    
    header_id_bytes = []
    for i in range(2): header_id_bytes.append(header_bytes[i])


url = "gmu.edu"
parse_response(get_response(url))
