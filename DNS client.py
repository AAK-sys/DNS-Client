import socket
import struct
import random
import time
import sys

# TO-DO: fix a major bug that breaks the program when www. is used
# Cause: a major bug where using www. causes a problem this is due to the change to the value of rd_length(becomes in the thousands/ reading the wrong values), putting this here so I don't forget

# get response from url

index_url_dict = {}

def get_response(URL):

    print("Preparing DNS query..")

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

    header_query = struct.pack('!HHHHHH', header[0], header[1], header[2], header[3], header[4], header[5])

    print("DNS query header=", header_query)

    #dynamic part of the query
    question = b''
    for i in URL.split('.'):
        question += struct.pack('B', len(i)) + i.encode('utf-8')
    question += b'\x00' #end of domain name marker
    question += struct.pack('!HH', 1, 1) #qtype and qclass

    print("DNS query question section=", question)

    packet = header_query + question
    print("Complete DNS query=", packet)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("Contacting DNS server..")
    print("Sending DNS query..")

    for i in range(1,4):
        sock.sendto(packet, ('8.8.8.8', 53))
        response, address = sock.recvfrom(1024)
        if(response!=None):
            print("DNS response received (attempt",i," of 3)")
            break
        elif(i==3):
            print("Request timed out")
            exit()
        time.sleep(5)
    sock.close()
    print("processing DNS response..")
    print('-' * 85)
    return [response, len(url.split('.'))]

#parse the dns server response
def parse_response(hexastring,url_size):
    # gmu.edu response example. Some websites have multiple IP addresses that the dns resolves hence multiple
    # hexadecimal responses or a longer hexadecimal. How this will affect the parsing is still unknown.

    # If standard response, process Header, Question, & Answer

    # Processing header -----------------------------------------------------------------------------
    header_bytes = []
    for i in range(12): header_bytes.append(hexastring[i])

    header_id = concatBytes(header_bytes[0], header_bytes[1])
    # Bit masking 1st half of 2nd row of bytes to get qr, opcode, aa, tc, & rd
    header_qr = 1
    header_opcode = header_bytes[2] & 30
    header_aa = header_bytes[2] & 32
    header_tc = header_bytes[2] & 64
    header_rd = 0
    # Bit masking 2nd half of 3rd row of bytes to get ra, z, & rcode
    header_ra = header_bytes[3] & 1
    header_z = header_bytes[3] & 14
    header_rcode = header_bytes[3] & 240
    header_qd_count = concatBytes(header_bytes[4], header_bytes[5])
    header_an_count = concatBytes(header_bytes[6], header_bytes[7])
    header_ns_count = concatBytes(header_bytes[8], header_bytes[9])
    header_ar_count = concatBytes(header_bytes[10], header_bytes[11])

    # Processing question ---------------------------------------------------------------------------
    # Keeps track of where we are in the hexastring
    pos = 12;
    # We may have more tha one question, so each one will be in an array
    questions = []
    Cname = []
    for i in range(0, 1):
        question = []
        domain = []
        # Getting domain/qname
        for j in range(url_size):
            count_octet = hexastring[pos]
            part = ""
            for z in range(count_octet):
                pos += 1
                part += chr(hexastring[pos])
            domain.append(part)
            pos += 1
        pos+=1
        question.append(domain)
        # Getting qtype
        qtype = concatBytes(hexastring[pos], hexastring[pos+1])
        pos += 2
        # Getting qclass
        qclass = concatBytes(hexastring[pos], hexastring[pos+1])
        pos += 2
        question.append(qtype)
        question.append(qclass)
        questions.append(question)
    resource_records = []
    for i in range(header_an_count):
        record =[]
        # Skipping RR name
        pos += 2
        # Getting record type
        rr_type = concatBytes(hexastring[pos], hexastring[pos+1])
        pos += 2
        record.append(rr_type)
        # Getting record class
        rr_class = concatBytes(hexastring[pos], hexastring[pos+1])
        pos += 2
        record.append(rr_class)
        # Getting TTL / time to live
        rr_ttl = concatBytes(concatBytes(concatBytes(hexastring[pos], hexastring[pos+1]), hexastring[pos+2]), hexastring[pos+3])
        pos += 4
        record.append(rr_ttl)
        # Getting rd length
        rr_rdlength = concatBytes(hexastring[pos], hexastring[pos+1])
        pos += 2
        record.append(rr_rdlength)
        # Getting rdata
        rr_rdata = []
        part = ""
        for j in range(rr_rdlength):
            if(rr_rdlength==4):
                rr_rdata.append(hexastring[pos])
                pos += 1
            else:
                count = hexastring[pos]
                if(not chr(count).isalpha()):
                    part+="."
                else:
                    part += chr(hexastring[pos])
                pos+=1
        part = part.strip(".")

        if(rr_rdlength==4):
            record.append(rr_rdata)
        else:
            record.append(part)
        resource_records.append(record)
    
    # Printing header section
    print("header.ID = ",header_id)
    print("header.QR = ",header_qr)
    print("header.OPCODE = ",header_opcode)
    print("header.AA = ",header_aa)
    print("header.TC = ",header_tc)
    print("header.RD = ",header_rd)
    print("header.RA = ",header_ra)
    print("header.Z = ",header_z)
    print("header.RCODE = ",header_rcode)
    print("header.QDCOUNT = ",header_qd_count)
    print("header.ANCOUNT = ",header_an_count)
    print("header.NSCOUNT = ",header_ns_count)
    print("header.ARCOUNT = ",header_ar_count)

    # Printing question section
    question = questions[0]
    print("question.QNAME = ",'.'.join(question[0]))
    print("question.QTYPE = ",question[1])
    print("question.QCLASS = ",question[2])
    
    # Printing answer section
    for val in resource_records:
        print("answer.NAME = ",'.'.join(question[0]))
        print("answer.TYPE = ",val[0])
        print("answer.CLASS = ",val[1])
        print("answer.TTL = ",val[2])
        print("answer.RDLENGTH = ",val[3])
        if(val[3]>4):
             print("answer.RDATA = ", val[4])
        else:
            print("answer.RDATA = ", ('.'.join(str(chr) for chr in val[4])) )


# Helper function that concats 2 octets into single 16 bit int, (all bin values must be in int form)
def concatBytes(x, y):
    res = x<<8 | y
    return res


# Testing Section.

url = "www.cnn.com"
if(len(sys.argv)>1):
    url = sys.argv[1]
#
info = get_response(url)
parse_response(info[0], info[1])
