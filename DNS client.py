import socket
import struct
import random



# get response from url
#TO-DO add time out functionality, and output the expected print messages
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

    # If standard response, process Header, Question, & Answer

    # Processing header -----------------------------------------------------------------------------
    header_bytes = []
    for i in range(12):
        header_bytes.append(hexastring[i])
    
    header_id_bytes = []
    for i in range(0, 1): header_id_bytes.append(header_bytes[i])

    # Bit masking 1st half of 2nd row of bytes to get qr, opcode, aa, tc, & rd
    header_qr = header_bytes[2] & 1
    header_opcode = header_bytes[2] & 30
    header_aa = header_bytes[2] & 32
    header_tc = header_bytes[2] & 64
    header_rd = header_bytes[2] & 128
    # Bit masking 2nd half of 2nd row of bytes to get ra, z, & rcode
    header_ra = header_bytes[3] & 1
    header_z = header_bytes[3] & 14
    header_rcode = header_bytes[3] & 240
    
    # Processing question ---------------------------------------------------------------------------
    question_bytes = []
    for i in range(3, 13): question_bytes.append(hexastring[i])

    question_qname_bytes = []
    question_qtype_bytes = []
    question_qclass_bytes = []
    for i in range(0, 5): question_qname_bytes.append(question_bytes[i])
    for i in range(6, 7): question_qtype_bytes.append(question_bytes[i])
    for i in range(8, 9): question_qclass_bytes.append(question_bytes[i])



url = "gmu.edu"
parse_response(b'\x05\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03gmu\x03edu\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x02{\x00\x04\x81\xae\x86\x1c')