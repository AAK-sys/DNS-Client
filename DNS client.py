import socket
import struct
import random
URL
# get response from url
def get_response(URL):
    #standard header for all queries change the sections marked if needed.
    header = []
    #header ID
    header.append(random.randint(1111,9999))
    #flags
    header.append(256)
    #qcount
    header.append(1)
    #anscount
    header.append(0)
    #authcount
    header.append(0)
    #additional count
    header.append(0)

    #dynamic part of the query
    question = b''
    for i in URL.split('.'):
        question += struct.pack('B', len(i)) + i.encode('utf-8')
    question += b'\x00' #end of domain name marker
    question += struct.pack('!HH', 1, 1) #qtype and qclass

    packet = struct.pack('!HHHHHH', header[0], header[1], header[2], header[3], header[4], header[5]) + question
    socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket.sendto(packet, ('8.8.8.8', 53))
    response, address = socket.recvfrom(16384)
    socket.close()

    return response

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
