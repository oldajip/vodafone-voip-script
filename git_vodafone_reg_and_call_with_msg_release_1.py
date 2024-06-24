from asyncio.windows_events import NULL
import numpy as np
import socket
import time
import uuid
import dns.resolver
import pydivert
import hashlib
import re
import random
import subprocess

# Vodafone VoIP Registration, Call and Pre-Recorded Message (WAV file)

# NOTE: The following was true at the time of development (June 2024)
#   - Vodafone was my service provider for Broadband and domestic VoIP
#   - I had a static IP provided by Vodafone
#   - Vodafone provided broadband PPPoE and VoIP settings

# NOTE: Vodafone does not appear to support number spoofing.
 
# The is how my environment is setup:
#
# 1. This was developed on Windows 11
#
# 2. Create a new conda environment with the additional packages: numpy, dnspython and pydivert 
#   conda create --name voip python=3.8
#   conda activate voip
#   pip install numpy
#   pip install dnspython
#   pip install pydivert
#
# 3. My Python IDE is Visual Studio Code
#   Ctrl-Shift-P 
#   Python: Select Interpreter
#   Select voip
#
# 4. Install FFmpeg - Only needed if you want the pre-recorded WAV message to be played
#   - The official site is https://ffmpeg.org/download.html
#   - I followed the links to download Windows Binaries (https://www.gyan.dev/ffmpeg/builds/)
#   - Copy the decompressed ffmpeg binaries onto the C: drive (assumed to be Windows install drive) 
#   - Add 'C:\ffmpeg\bin' to the end of the PATH (Environmental Variables...)
#   - Reboot the computer for PATH changes to take effect
#   - Alternatively you can ask ChatGPT to develop the PCMA encoding (G.711 A-law encoding), but it won't sound good.
#   - Vodafone supports more than just PCMA, but one codec is much like another for testing
#
# 5. IMPORTANT - RUN YOUR IDE (Visual Studio Code) AS ADMINISTRATOR
#   - The SIP/SDP and RTP packets require their Differentiated Services Field altered to 
#   prioritise the packets through the network. I could only do this with pydivert.WinDivert 
#   (using sock.setsockopt didn't work for me).
#   - If you still get 'PermissionError: [WinError 5] Access is denied' then run the script from the
#   Anaconda Prompt (with Administrator privilages)
#
# 6. The purpose of the WAV message is to test that audio is making it through the network.
#   - Vodafone appears to permit local RTP ports 10000 to 10010 (ideally 10000). If you set 
#   RTP_LOCAL_PORT to anything else then the audio probably won't make it to the remote phone
#   - If you want to use the provided WAV file 'voipTest.wav' it should be stored in 'C:\Temp'
#   or any location that has read/write access. If you store it elsewhere or use your own WAV be
#   sure to update 'WAV_INPUT_FILE_NAME' and 'PCMA_OUTPUT_FILE_NAME'
#
# 7. Wireshark is your friend
#   - Filter on SIP and RTP
#   - I use an ETAP-2003 (TAP) to monitor the traffic between router and Ethernet/Fibre converter
#
# 8. ChatGPT is mostly your friend
#   - Development would have taken much longer without it.
#
# 9. This code isn't well written
#   - I wrote it to understand why Vodafone works wth Grandstream but not Yealink. Feel free to rewrite it.
#   - For info - The Yealink User-Agent field (Yealink W70B aaa.bbb.ccc.ddd) is incompatible with Vodafone,
#   which only accepts 'Vox 3.0v' or similar
#
# In order to make this work you will need the following information from Vodafone:
#   - SIP USERNAME (something like voi0123456789)
#   - SIP PASSWORD
#   - SIP URI (If this is different to the username then the code may not work)
#   - OUTBOUND PROXY (there are several, it should be something like xxx.zz.bbvoice.vodafone.co.uk)
#   - SIP REGISTRAR SERVER (I've left this in the code as resvoip.vodafone.co.uk)
#   - Static IP (There are ways round this with DDNS, or just use the currently assigned IP, but static is best)
#
# My router sits on the fibre boundry (i.e. not behind another router). 
# It required no Port Forward, no altered Firewall Rules and no Static Routes to work. 
# I do not have SIP-ALG enabled.
# Your mileage may vary. Note that a TAP will help determine if packets are getting lost or blocked.

# Configuration for SIP registration
REALM = "vodafone.co.uk"                                    # Should be fine as is
SIP_SERVER = "resvoip.vodafone.co.uk"                       # Replace with the one supplied by Vodafone
PROXY_SERVER = "xxx.zz.bbvoice.vodafone.co.uk"              # Replace with the one supplied by Vodafone
USERNAME = "voi0123456789"                                  # Replace with the one supplied by Vodafone
PASSWORD = "ABCDEFG"                                        # Replace with the one supplied by Vodafone
LOCAL_IP = "10.10.10.10"                                    # Replace with the IP of the computer running this code
INTERNET_IP = "123.123.123.123"                             # Replace with your Internet IP (ideally a static IP)

NAME = "AnyName"                                            # Whatever you want within reason

SIP_PORT = 5060                                             # Don't change this
LOCAL_PORT = 5065                                           # Don't change this
RTP_LOCAL_PORT = 10000                                      # Must be between 10000 and 10010 (inclusive). ideally 10000

REMOTE_PHONE_NUMBER = "01234567890"                         # The phone number you want to call
CALLER_PHONE_NUMBER = "09876543210"                         # Your Vodafone provided phone number - seems to be ignored

DSCP_VALUE = 0x68                                           # Differentiated Services Code Point for SIP
DSCP_RTP_VALUE = 0xB8                                       # Differentiated Services Code Point for RTP
CSEQ = 0                                                    # Sequence ID
SESSION_ID = 20000                                          # Seems to work
SESSION_VERSION = 20000                                     # Seems to work
USER_AGENT = "Vox 3.0v"                                     # Works with Vodafone
MAX_FORWARDS = 70                                           # Not that important

# Message to play
WAV_INPUT_FILE_NAME = 'C:\\Temp\\voipTest.wav'              # WAV file to play
PCMA_OUTPUT_FILE_NAME = 'C:\\Temp\\voipTest.alaw'           # PCMA (alaw) temporary file created by FFmpeg

def increment_cseq():
    global CSEQ
    CSEQ += 1
    return CSEQ

def increment_session_id():
    global SESSION_ID
    SESSION_ID += 1
    return SESSION_ID

def increment_session_version():
    global SESSION_VERSION
    SESSION_VERSION += 1
    return SESSION_VERSION

# Resolve SRV record and return ordered list of proxy servers
def resolve_srv(srv_record):
    answers = dns.resolver.resolve(srv_record, 'SRV')
    srv_hosts = sorted(
        [(rdata.priority, rdata.weight, str(rdata.target).rstrip('.')) for rdata in answers],
        key=lambda x: (x[0], -x[1])
    )
    return srv_hosts   
       
# Generate a unique branch parameter
def generate_branch():
    return f"z9hG4bK{uuid.uuid4().hex}"      
    
# Function to extract the 'To' tag from a SIP response
def extract_to_tag(response):
    match = re.search(r'To:.*?tag=([\w\-]+)', response)
    if match:
        return match.group(1)
    return None    

# Function to extract the 'From' tag from a SIP response
def extract_from_tag(response):
    match = re.search(r'From:.*?tag=([\w\-]+)', response)
    if match:
        return match.group(1)
    return None   

# Function to extract the branch value from 'Via'
def extract_branch(response):
    match = re.search(r"Via:.*?branch=([\w\-\.]+)", response)    
    if match:
        return match.group(1)
    return None

# Function to extract the CSeq value
def extract_cseq(response):
    match = re.search(r"CSeq: (\d+)", response)
    if match:
        return match.group(1)
    return None

# Function to extract the Call-Id value
def extract_call_id(response):
    match = re.search(r"Call-ID: (.+)", response)
    if match:
        return match.group(1).strip()
    return None

# Extract the IP address and port number from 'Via'
def extract_ip_port(via_line):
    pattern = r"Via: SIP\/2\.0\/UDP ([\d\.]+):(\d+);"
    match = re.search(pattern, via_line)
    if match:
        ip_address = match.group(1)
        port_number = match.group(2)
        return ip_address, port_number
    return None, None

# Function to extract the remote media port value
def extract_media_port(response):
    match = re.search(r"\baudio (\d+) RTP\/AVP\b", response)
    if match:
        return match.group(1)
    return None

# Function to register a new SIP binding
def register(sock, dest_ip, dest_port, sip_server, local_port, internet_ip, username, call_id, from_tag, 
             contact_uuid, proxy_server, expires=120):
    print("Registration Request")
    register_request = create_register_request(
        sip_server, local_port, dest_port, internet_ip, username, call_id, 
        from_tag, contact_uuid, proxy_server, expires)
    send_with_dscp(sock, register_request, dest_ip, dest_port, DSCP_VALUE)      
    responses = listen_for_responses(sock, timeout=5)
    return responses

def authorise(sock, dest_ip, dest_port, sip_server, local_port, internet_ip, username, call_id, from_tag, 
              contact_uuid, proxy_server, uri, realm, nonce, auth_response, expires=120):   
    print("Authorisation Request")     
    #uri = f"sip:{sip_server}:{dest_port}"    
    auth = create_auth(uri, username, realm, nonce, auth_response)
    proxy_auth = f"Proxy-Authorization: {auth}\r"
    auth_request = create_register_request(
        sip_server, local_port, dest_port, internet_ip, username, call_id, 
        from_tag, contact_uuid, proxy_server, expires, proxy_auth)     
    send_with_dscp(sock, auth_request, dest_ip, dest_port, DSCP_VALUE)      
    responses = listen_for_responses(sock, timeout=5)    
    return responses  

def invite(sock, dest_ip, dest_port, sip_server, local_port, internet_ip, username, call_id, from_tag,  
             contact_uuid, proxy_server, cseq, branch, session_id, session_version):
    print("Initiate phone call")     
    invite_request = create_invite_request(
        sip_server, internet_ip, local_port, dest_port, username, call_id, 
        cseq, from_tag, branch, session_id, session_version)
    send_with_dscp(sock, invite_request, dest_ip, dest_port, DSCP_VALUE)      
    responses = listen_for_responses(sock, timeout=5)
    return responses

def invite_auth_ack(sock, dest_ip, dest_port, sip_server, local_port, internet_ip, username, call_id, from_tag, to_tag, 
                    contact_uuid, proxy_server, cseq, branch):
    print("Acknowledge authentication request") 
    auth_ack_response = create_remote_phone_ack_response(
        sip_server, internet_ip, local_port, dest_port, username, call_id, 
        cseq, from_tag, to_tag, branch)    
    send_with_dscp(sock, auth_ack_response, dest_ip, dest_port, DSCP_VALUE)      
    return    

def invite_auth(sock, dest_ip, dest_port, sip_server, local_port, internet_ip, username, call_id, from_tag, 
                contact_uuid, proxy_server, uri, cseq, branch, session_id, session_version, realm, nonce, auth_response):
    print("Authenticate phone call")     
    auth = create_auth(uri, username, realm, nonce, auth_response)      
    proxy_auth = f"Proxy-Authorization: {auth}\r"    
    invite_request = create_invite_request(
        sip_server, internet_ip, local_port, dest_port, username, call_id, 
        cseq, from_tag, branch, session_id, session_version, proxy_auth)
    send_with_dscp(sock, invite_request, dest_ip, dest_port, DSCP_VALUE)      
    responses = listen_for_responses(sock, timeout=7)
    return responses

def cancel_invite(sock, dest_ip, dest_port, sip_server, local_port, internet_ip, username, call_id, from_tag, to_tag, contact_uuid, proxy_server, cseq, branch):
    print("Send CANCEL")    
    cancel_request = create_cancel_invite_request(
        sip_server, internet_ip, local_port, dest_port, username, call_id, 
        cseq, from_tag, to_tag, branch)      
    send_with_dscp(sock, cancel_request, dest_ip, dest_port, DSCP_VALUE)      
    responses = listen_for_responses(sock, timeout=5)
    return responses   

def invite_bye(sock, dest_ip, dest_port, sip_server, local_port, internet_ip, username, call_id, from_tag, to_tag, 
               contact_uuid, proxy_server, cseq, branch):
    print("Send BYE to end the call") 
    bye_request = create_invite_bye_request(
        sip_server, internet_ip, local_port, dest_port, username, call_id, 
        cseq, from_tag, to_tag, branch)      
    send_with_dscp(sock, bye_request, dest_ip, dest_port, DSCP_VALUE)      
    responses = listen_for_responses(sock, timeout=5)    
    return responses

def invite_ok_ack(sock, dest_ip, dest_port, sip_server, local_port, internet_ip, username, call_id, from_tag, to_tag, 
                  contact_uuid, proxy_server, cseq, branch):
    print("Acknowledge invite OK") 
    ack_response = create_ok_ack_response(sip_server, internet_ip, local_port, dest_port, username, 
                                          call_id, cseq, from_tag, to_tag, branch)    
    send_with_dscp(sock, ack_response, dest_ip, dest_port, DSCP_VALUE)      
    return  

def invite_bye_ack(sock, dest_ip, dest_port, sip_server, local_port, internet_ip, username, call_id, from_tag, to_tag, 
                  contact_uuid, proxy_server, cseq, branch):
    print("Acknowledge invite BYE") 
    ack_response = create_bye_ack_response(sip_server, internet_ip, local_port, dest_port, username, 
                                           call_id, cseq, from_tag, to_tag, branch)    
    send_with_dscp(sock, ack_response, dest_ip, dest_port, DSCP_VALUE)      
    return

def invite_ok_bye_response(sock, dest_ip, dest_port, sip_server, local_port, internet_ip, remote_ip, remote_port, 
                           username, call_id, from_tag, to_tag, contact_uuid, proxy_server, cseq, branch):    
    print("Acknowledge BYE response with OK") 
    ack_response = create_ok_response_for_bye(sip_server, internet_ip, local_port, dest_port, remote_ip, 
                                              remote_port, username, call_id, cseq, from_tag, to_tag, branch)    
    send_with_dscp(sock, ack_response, dest_ip, dest_port, DSCP_VALUE)      
    return                                    

# Function to create a an authorisation field
def create_auth(uri, username, realm, nonce, authResponse):    
    auth = f"Digest username=\"{username}\",realm=\"{realm}\",nonce=\"{nonce}\",uri=\"{uri}\",response=\"{authResponse}\",algorithm=MD5"       
    return auth

def listen_for_type_responses(sock, timeout=5, immediate_responses=None):
    end_time = time.time() + timeout
    responses = []
    if immediate_responses is None:
        immediate_responses = []
    
    while time.time() < end_time:
        sock.settimeout(max(0, end_time - time.time()))
        try:
            data, addr = sock.recvfrom(4096)
            response = data.decode()
            responses.append(response)
            
            # Check for immediate responses
            for immediate_response in immediate_responses:
                if immediate_response in response:
                    return responses            
                                        
        except socket.timeout:
            break
    return responses   

# Function to listen for SIP responses within a given timeout
def listen_for_responses(sock, timeout=5):   
    return listen_for_type_responses(sock, timeout, 
                                     ["407 Proxy Authentication Required", 
                                      "200 Registration Successful", 
                                      "603 Decline"])

# Function to calculate the authorisation reponse
def calculate_response(username, realm, password, method, uri, nonce):
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return response 
 
# Function to create a REGISTER request
def create_register_request(sip_server, local_port, dest_port, internet_ip, username, 
                            call_id, tag, contact_uuid, proxy_server, 
                            expires=120, auth_header=""):
    
    branch = generate_branch()  
    cseq = increment_cseq()
    
    register_request = (
        f"REGISTER sip:{sip_server} SIP/2.0\r"
        f"Via: SIP/2.0/UDP {internet_ip}:{local_port};rport;branch={branch}\r"
        f"From: \"{NAME}\" <sip:{username}@{sip_server}>;tag={tag}\r"      
        f"To: <sip:{username}@{sip_server}>\r"
        f"Call-ID: {call_id}\r"
        f"CSeq: {cseq} REGISTER\r"
        f"Contact: <sip:{username}@{internet_ip}:{local_port}>\r"
        f"Max-Forwards: {MAX_FORWARDS}\r"
        f"User-Agent: {USER_AGENT}\r" 
        "Supported: path\r"
        f"Expires: {expires}\r"
        f"{auth_header}"    
        "Content-Length: 0\r\r"            
    )   
    return register_request

# Function to create an INVITE request with SDP
def create_invite_request(sip_server, internet_ip, local_port, dest_port, username, call_id, cseq, tag, branch, session_id, session_version, auth_header=""):    
    sdp_body = (
        "v=0\r"
        f"o={username} {session_id} {session_version} IN IP4 {internet_ip}\r"
        "s=SIP data\r"
        f"c=IN IP4 {internet_ip}\r"
        "t=0 0\r"
        f"m=audio {RTP_LOCAL_PORT} RTP/AVP 8\r"
        "a=sendrecv\r"
        "a=rtpmap:8 PCMA/8000\r"
        "a=ptime:20\r"
    )
    invite_request = (
        f"INVITE sip:{REMOTE_PHONE_NUMBER}@{sip_server}:{dest_port} SIP/2.0\r"
        f"Via: SIP/2.0/UDP {internet_ip}:{local_port};rport;branch={branch}\r"
        f"From: \"{NAME}\" <sip:{username}@{sip_server}:{dest_port}>;tag={tag}\r"
        f"To: <sip:{REMOTE_PHONE_NUMBER}@{sip_server}:{dest_port}>\r"       
        f"Call-ID: {call_id}\r"
        f"CSeq: {cseq} INVITE\r"     
        f"Contact: <sip:{username}@{internet_ip}:{local_port}>\r"
        "Content-Type: application/sdp\r"
        "Allow: INVITE, INFO, PRACK, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REGISTER, SUBSCRIBE, REFER, PUBLISH, UPDATE, MESSAGE\r" 
        f"Max-Forwards: {MAX_FORWARDS}\r"   
        f"User-Agent: {USER_AGENT}\r"    
        "Allow-Events: talk,hold,conference,refer,check-sync\r"         
        "Supported: replaces\r"
        f"{auth_header}"
        f"Content-Length: {len(sdp_body)}\r\r"
        f"{sdp_body}"     
    )
    return invite_request

# Function to create a CANCEL INVITE request
def create_cancel_invite_request(sip_server, internet_ip, local_port, dest_port, username, call_id, cseq, from_tag, to_tag, branch):
    cancel_request = (
        f"CANCEL sip:{REMOTE_PHONE_NUMBER}@{sip_server}:{dest_port} SIP/2.0\r"
        f"Via: SIP/2.0/UDP {internet_ip}:{local_port};rport;branch={branch}\r"     
        f"From: \"{NAME}\" <sip:{username}@{sip_server}:{dest_port}>;tag={from_tag}\r"
        f"To: <sip:{REMOTE_PHONE_NUMBER}@{sip_server}:{dest_port}>\r"
        f"Call-ID: {call_id}\r"
        f"CSeq: {cseq} CANCEL\r"  
        f"Max-Forwards: {MAX_FORWARDS}\r"
        f"User-Agent: {USER_AGENT}\r"        
        "Content-Length: 0\r\r"
    )
    return cancel_request

# Function to create a invite BYE request
def create_invite_bye_request(sip_server, internet_ip, local_port, dest_port, username, call_id, cseq, from_tag, to_tag, branch):
    bye_request = (
        f"BYE sip:{REMOTE_PHONE_NUMBER}@{sip_server} SIP/2.0\r"
        f"Via: SIP/2.0/UDP {internet_ip}:{local_port};rport;branch={branch}\r"     
        f"From: \"{NAME}\" <sip:{CALLER_PHONE_NUMBER}@{sip_server}>;tag={from_tag}\r"
        f"To: <sip:{REMOTE_PHONE_NUMBER}@{sip_server}>;tag={to_tag}\r"
        f"Call-ID: {call_id}\r"
        f"CSeq: {cseq} BYE\r"  
        f"Contact: <sip:{username}@{internet_ip}>\r"
        f"Max-Forwards: {MAX_FORWARDS}\r"
        f"User-Agent: {USER_AGENT}\r"        
        "Content-Length: 0\r\r"
    )    
    return bye_request

# Function to create a 'REMOTE PHONE' ACK request
def create_remote_phone_ack_response(sip_server, internet_ip, local_port, dest_port, username, call_id, cseq, from_tag, to_tag, branch):
    ack = (
        f"ACK sip:{REMOTE_PHONE_NUMBER}@{sip_server}:{dest_port} SIP/2.0\r"
        f"Via: SIP/2.0/UDP {internet_ip}:{local_port};rport;branch={branch}\r"
        f"From: \"{NAME}\" <sip:{username}@{sip_server}>;tag={from_tag}\r"
        f"To: <sip:{REMOTE_PHONE_NUMBER}@{sip_server}:{dest_port}>;tag={to_tag}\r"
        f"Max-Forwards: {MAX_FORWARDS}\r"
        f"Call-ID: {call_id}\r"
        f"CSeq: {cseq} ACK\r"
        "Content-Length: 0\r\r"
    )
    return ack

# Function to create a 'OK' ACK response
def create_ok_ack_response(sip_server, internet_ip, local_port, dest_port, username, call_id, cseq, from_tag, to_tag, branch):
    ack = (
        f"ACK sip:{REMOTE_PHONE_NUMBER}@{sip_server} SIP/2.0\r"
        f"Via: SIP/2.0/UDP {internet_ip}:{local_port};rport;branch={branch}\r"
        f"From: \"{NAME}\" <sip:{CALLER_PHONE_NUMBER}@{sip_server}>;tag={from_tag}\r"
        f"To: <sip:{REMOTE_PHONE_NUMBER}@{sip_server}>;tag={to_tag}\r"
        f"Max-Forwards: {MAX_FORWARDS}\r"
        f"Call-ID: {call_id}\r"
        f"CSeq: {cseq} ACK\r"
        f"Contact: <sip:{username}@{internet_ip}>\r"        
        "Content-Length: 0\r\r"
    )    
    return ack    

# Function to create a 'BYE' ACK response
def create_bye_ack_response(sip_server, internet_ip, local_port, dest_port, username, call_id, cseq, from_tag, to_tag, branch):
    ack = (
        f"ACK sip:{REMOTE_PHONE_NUMBER}@{sip_server} SIP/2.0\r"
        f"Via: SIP/2.0/UDP {internet_ip}:{local_port};rport;branch={branch}\r"
        f"From: \"{NAME}\" <sip:{CALLER_PHONE_NUMBER}@{sip_server}>;tag={from_tag}\r"
        f"To: <sip:{REMOTE_PHONE_NUMBER}@{sip_server}>;tag={to_tag}\r"
        f"Max-Forwards: {MAX_FORWARDS}\r"
        f"Call-ID: {call_id}\r"
        f"CSeq: {cseq} ACK\r"
        f"Contact: <sip:{username}@{internet_ip}>\r"        
        "Content-Length: 0\r\r"
    )    
    return ack  

def create_ok_response_for_bye(sip_server, internet_ip, local_port, dest_port, remote_ip, 
                               remote_port, username, call_id, cseq, from_tag, to_tag, branch):
    
    ack = (
        f"SIP/2.0 200 OK\r"
        f"Via: SIP/2.0/UDP {remote_ip}:{remote_port};rport;branch={branch}\r"
        f"From: <sip:{REMOTE_PHONE_NUMBER}@{remote_ip}>;tag={from_tag}\r"
        f"To: \"{NAME}\" <sip:{username}@{internet_ip}>;tag={to_tag}\r"
        f"Call-ID: {call_id}\r"
        f"CSeq: {cseq} BYE\r"
        f"Contact: <sip:{username}@{internet_ip}:{local_port}>\r"       
        f"User-Agent: {USER_AGENT}\r"         
        "Supported: replaces\r"
        "Content-Length: 0\r\r"
    )        
    
    #ack = (
    #    f"SIP/2.0 200 OK\r"
    #    f"Via: SIP/2.0/UDP {internet_ip}:{local_port};rport;branch={branch}\r"
    #    f"From: \"{NAME}\" <sip:{CALLER_PHONE_NUMBER}@{sip_server}>;tag={from_tag}\r"
    #    f"To: <sip:{REMOTE_PHONE_NUMBER}@{sip_server}>;tag={to_tag}\r"
    #    f"Call-ID: {call_id}\r"
    #    f"CSeq: {cseq} BYE\r"
    #    f"Contact: <sip:{username}@{internet_ip}>\r"        
    #    "Content-Length: 0\r\r"
    #)    
    return ack  

#create_bye_ack_response(sip_server, internet_ip, local_port, dest_port, username, call_id, cseq, from_tag, to_tag, branch)  
    
# Function to send packet with modified DSCP value
# THIS REQUIRES ADMINISTRATION PRIVILAGES. RUN PYTHON CODE AS ADMIN.
def send_with_dscp(sock, packet_data, dest_ip, dest_port, dscp_value):
    with pydivert.WinDivert(f"udp.DstPort == {dest_port} and udp.PayloadLength > 0") as w:    
        sock.sendto(packet_data.encode(), (dest_ip, dest_port))

        # Capture and modify the outgoing packet
        packet = w.recv()
        if packet.src_addr == LOCAL_IP and packet.dst_addr == dest_ip:
            packet.ipv4.tos = dscp_value        # Set DSCP value
            w.send(packet)
                 
# Function to remove an existing binding (if any), register a new binding and then authorise that registration
def registerSIP():        
    # Get list of proxy servers
    proxy_servers = resolve_srv(f"_sip._udp.{PROXY_SERVER}")

    if proxy_servers:    
        # Create a socket for UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((LOCAL_IP, LOCAL_PORT))    

        # Iterate proxy servers in order of priority and weight
        for priority, weight, proxy_server in proxy_servers:
            try:
                proxy_server_ip = socket.gethostbyname(proxy_server)
            except socket.gaierror:
                print(f"Cannot resolve hostname: {proxy_server}")
                continue    
            
            # Generate unique call ID and tag for registration process
            tag = uuid.uuid4()
            contact_uuid = uuid.uuid4()
            call_id = uuid.uuid4()
            #call_id = f"{uuid.uuid4()}@AB.CDE.F.GHI"  
                        
            # Register new binding and listen for responses
            responses = register(sock, proxy_server_ip, SIP_PORT, SIP_SERVER, LOCAL_PORT, INTERNET_IP, USERNAME, 
                                 call_id, tag, contact_uuid, proxy_server)        
            
            # Is there a supposed server errror
            if any("500 Internal Server Error" in response for response in responses):
                for response in responses:
                    if "500 Internal Server Error" in response:                
                        # We're done
                        print(f"Apparently there's a server error, not sure I believe it but here's the response: \n{response}") 
                        sock.close() 
                        return (False, NULL, NULL, NULL, NULL, NULL, NULL)                       
            
            # Is authorisation required   
            if any("407 Proxy Authentication Required" in response for response in responses):
                # Extract the realm and nonce from the 407 response
                for response in responses:
                    if "407 Proxy Authentication Required" in response:
                        realm_index = response.find("realm=") + 7
                        realm_end_index = response.find(",", realm_index) - 1
                        realm = response[realm_index:realm_end_index]
                                                                  
                        nonce_index = response.find("nonce=") + 7
                        nonce_end_index = response.find("\"", nonce_index)
                        nonce = response[nonce_index:nonce_end_index]                        
                        break  
                                                                           
                # Calculate the response for the Authorisation header
                uri = f"sip:{SIP_SERVER}:{SIP_PORT}"
                auth_response = calculate_response(USERNAME, realm, PASSWORD,"REGISTER", uri, nonce)  
                                                       
                # Authorise binding and listen for responses
                responses = authorise(sock, proxy_server_ip, SIP_PORT, SIP_SERVER, LOCAL_PORT, INTERNET_IP, USERNAME, 
                                      call_id, tag, contact_uuid, proxy_server, uri, realm, nonce, auth_response)                                                         
                if responses:
                    if any("200 Registration Successful" in response for response in responses):                    
                        print("Successfully registered with SIP server")  
                        return (True, sock, proxy_server_ip, call_id, tag, contact_uuid, proxy_server)                                             
                    else:
                        print("Failed to register with SIP server") 
                        sock.close() 
                        return (False, NULL, NULL, NULL, NULL, NULL, NULL) 
                                                   
            # No repetition, if it fails then it fails!
            print("It's Wireshark time!")        
        
    # Close the socket
    sock.close()        
    return (False, NULL, NULL, NULL, NULL, NULL, NULL)           
        
def initiatePhoneCall(sock, proxy_server_ip, call_id, tag, contact_uuid, proxy_server):
    # Attempt to establish a phone call
    cseq = increment_cseq()                      
    branch = generate_branch()  
    session_id = increment_session_id()
    session_version = SESSION_VERSION
                        
    responses_1 = invite(sock, proxy_server_ip, SIP_PORT, SIP_SERVER, LOCAL_PORT, INTERNET_IP, USERNAME, 
                       call_id, tag, contact_uuid, proxy_server, cseq, branch, session_id, session_version)  
    
    # If there is no response from the server then something has gone too wrong to recover from
    if not responses_1:
        print("No server response to INVITE request. Exiting.")
        sock.close()   
        return     
              
    if any("407 Proxy Authentication Required" in response for response in responses_1):        
        # Extract the realm and nonce from the 407 response
        for response in responses_1:
            if "407 Proxy Authentication Required" in response:
                realm_index = response.find("realm=") + 7
                realm_end_index = response.find(",", realm_index) - 1
                realm = response[realm_index:realm_end_index]
                                                            
                nonce_index = response.find("nonce=") + 7
                nonce_end_index = response.find("\"", nonce_index)
                nonce = response[nonce_index:nonce_end_index]
                
                to_tag = extract_to_tag(response)        
                break  
                            
        # The server will expect an acknowledgement
        invite_auth_ack(sock, proxy_server_ip, SIP_PORT, SIP_SERVER, LOCAL_PORT, INTERNET_IP, USERNAME, call_id, tag, to_tag, contact_uuid, proxy_server, cseq, branch)                            
                            
        # Authorization required            
        print(f"Authentication Required. Realm: \"{realm}\". Nonce: \"{nonce}\"")    
                
        # Calculate the INVITE authorisation response
        to_tag = 0
        cseq = increment_cseq() 
        uri = f"sip:{REMOTE_PHONE_NUMBER}@{SIP_SERVER}:{SIP_PORT}"
        auth = calculate_response(USERNAME, realm, PASSWORD, "INVITE", uri, nonce)                   
        responses_2 = invite_auth(sock, proxy_server_ip, SIP_PORT, SIP_SERVER, LOCAL_PORT, INTERNET_IP, USERNAME, call_id, tag, 
                                contact_uuid, proxy_server, uri, cseq, branch, session_id, session_version, realm, nonce, auth)  
        
        # If there's no response from the server then it's beyond recovery
        if not responses_2:
            print("No server response to INVITE AUTHENTICATION request. Exiting.")
            sock.close()   
            return          
        
        is_failed = False
        call_established = False
        rcv_media_remote_port = None
        if any("603 Decline" or "180 Ringing" or "200 OK" or "183 Session Description" in response for response in responses_2):            
            for response in responses_2:
                if "603 Decline" in response:
                    print(f"Fail!. Server says No.")   
                    to_tag = extract_to_tag(response)  
                    is_failed = True
                    continue      
                
                if "183 Session Description" in response:                 
                    to_tag = extract_to_tag(response)    
                    port = extract_media_port(response)   
                    if (port): 
                        rcv_media_remote_port = port  
                        print(f"Session Description...To Tag: {to_tag}. Remote port: {rcv_media_remote_port}")                      
                    continue                             
                
                if "180 Ringing" in response:
                    print("Ringing...")                       
                    to_tag = extract_to_tag(response)    
                    continue                       
                
                if "200 OK" in response:
                    print("Call established")
                    to_tag = extract_to_tag(response)    
                    call_established = True    
                    continue                  
                            
            if to_tag == 0:
                print("Failed to extract to tag. No way to correctly identify sender. quit!")
                sock.close()   
                return    
            
            # The server will expect an acknowledgement
            invite_auth_ack(sock, proxy_server_ip, SIP_PORT, SIP_SERVER, LOCAL_PORT, INTERNET_IP, USERNAME, call_id, tag, to_tag, contact_uuid, proxy_server, cseq, branch)  
            
            # The exchange failed, probably because the server declined us so exit
            if is_failed:
                print("Failed. Close socket and terminate")
                sock.close()   
                return                    
                                                                        
            # Initialize the last response time to the current time
            last_response_time = time.time()            
            
            # Lets just wait until the other end finishes the call or doesn't answer
            print("Listen for responses from server")
            is_call_made = False
            while (True):
                response_keyword = ["200 OK", "BYE sip", "ACK sip", "CANCEL sip"]
                responses_4 = listen_for_type_responses(sock, timeout=3, immediate_responses=response_keyword)   
                
                if responses_4:
                    # Update the last response time to the current time
                    last_response_time = time.time()  
                
                for response in responses_4:                    
                    if any(keyword in response for keyword in response_keyword):                       
                        # Extract as much as possible
                        rcv_remote_ip, rcv_remote_port = extract_ip_port(response)
                        rcv_call_id = extract_call_id(response)
                        rcv_cseq = extract_cseq(response) 
                        rcv_from_tag = extract_from_tag(response)              
                        rcv_to_tag = extract_to_tag(response)         
                        rcv_branch = extract_branch(response)    
                        rcv_media_remote_port = extract_media_port(response)   
                        
                    if "200 OK" in response:    
                        print("Received OK from Server")                                                                                                     
                        invite_ok_ack(sock, proxy_server_ip, SIP_PORT, SIP_SERVER, LOCAL_PORT, INTERNET_IP, USERNAME, 
                                      rcv_call_id, rcv_from_tag, rcv_to_tag, contact_uuid, proxy_server, rcv_cseq, rcv_branch)       
                        
                        # Play audio message if not already done and call established
                        #if (not is_call_made) and (call_established):
                        if not is_call_made:
                            is_call_made = True
                            time.sleep(1) 
                            print("Send WAV AUDIO message")                        
                            send_audio_message(WAV_INPUT_FILE_NAME, PCMA_OUTPUT_FILE_NAME, LOCAL_IP, RTP_LOCAL_PORT, proxy_server_ip, int(rcv_media_remote_port))
                            print("WAV AUDIO message sent")
                            
                            # Time to say bye!
                            cseq = increment_cseq() 
                            invite_bye(sock, proxy_server_ip, SIP_PORT, SIP_SERVER, LOCAL_PORT, INTERNET_IP, USERNAME, call_id, 
                                        tag, to_tag, contact_uuid, proxy_server, cseq, branch)                        
                        continue        
                        
                    elif "ACK sip" in response:   
                        print("Received ACK from Server")                          
                        invite_ok_ack(sock, proxy_server_ip, SIP_PORT, SIP_SERVER, LOCAL_PORT, INTERNET_IP, USERNAME, 
                                      rcv_call_id, rcv_from_tag, rcv_to_tag, contact_uuid, proxy_server, rcv_cseq, rcv_branch)   
                        continue   
                        
                    elif "BYE sip" in response:   
                        print("Received BYE from Server") 
                        invite_ok_bye_response(sock, proxy_server_ip, SIP_PORT, SIP_SERVER, LOCAL_PORT, INTERNET_IP, rcv_remote_ip, rcv_remote_port, 
                                               USERNAME, rcv_call_id, rcv_from_tag, rcv_to_tag, contact_uuid, proxy_server, rcv_cseq, rcv_branch)    
                        print("Test complete")
                        sock.close()    
                        return  
                    
                    elif "CANCEL sip" in response:    
                        print("Received CANCEL from Server...no response prepared")
                        #invite_ok_cancel_response(sock, proxy_server_ip, SIP_PORT, SIP_SERVER, LOCAL_PORT, INTERNET_IP, USERNAME, 
                        #                          rcv_call_id, rcv_from_tag, rcv_to_tag, contact_uuid, proxy_server, rcv_cseq, rcv_branch)    
                        continue                     
                        
                if (not is_call_made) and (rcv_media_remote_port) and (call_established) and (time.time() - last_response_time > 3): 
                    # Play audio message after timeout - remember that asome time will have eleapsed whilst awaiting a response!
                    is_call_made = True
                    print("Time-out reached - send WAV AUDIO message")                        
                    send_audio_message(WAV_INPUT_FILE_NAME, PCMA_OUTPUT_FILE_NAME, LOCAL_IP, RTP_LOCAL_PORT, proxy_server_ip, int(rcv_media_remote_port))
                    print("WAV AUDIO message sent")
                    
                    # Time to say bye!
                    cseq = increment_cseq() 
                    invite_bye(sock, proxy_server_ip, SIP_PORT, SIP_SERVER, LOCAL_PORT, INTERNET_IP, USERNAME, call_id, 
                                    tag, to_tag, contact_uuid, proxy_server, cseq, branch)                    
                                                                                
                # Check if the idle time has exceeded the maximum allowed time
                if time.time() - last_response_time > 40:
                    print("No response received for more than 40 seconds. Exiting...")
                    break                                                                                                                                                 
                                                                     
        print("Test complete")
        sock.close()             
    return
       
def send_rtp_packet(sock, data, local_ip, local_port, rmt_addr, rmt_port, sequence_number, timestamp, ssrc, payloadType):
    rtp_header = bytearray(12)
    rtp_header[0] = 0x80  # Version 2, no padding, no extension, 0 CSRCs
    rtp_header[1] = payloadType  # Payload type 8 (PCMA), Marker bit set to 1 for the first packet
    rtp_header[2] = (sequence_number >> 8) & 0xFF
    rtp_header[3] = sequence_number & 0xFF
    rtp_header[4] = (timestamp >> 24) & 0xFF
    rtp_header[5] = (timestamp >> 16) & 0xFF
    rtp_header[6] = (timestamp >> 8) & 0xFF
    rtp_header[7] = timestamp & 0xFF
    rtp_header[8] = (ssrc >> 24) & 0xFF
    rtp_header[9] = (ssrc >> 16) & 0xFF
    rtp_header[10] = (ssrc >> 8) & 0xFF
    rtp_header[11] = ssrc & 0xFF

    rtp_packet = rtp_header + data    
    send_rtp_with_dscp(sock, rtp_packet, local_ip, rmt_addr, rmt_port, DSCP_RTP_VALUE)
    return

def send_rtp_with_dscp(sock, packet_data, local_ip, dest_ip, dest_port, dscp_value):
    with pydivert.WinDivert(f"udp.DstPort == {dest_port} and udp.PayloadLength > 0") as w:
        sock.sendto(packet_data, (dest_ip, dest_port))

        # Capture and modify the outgoing packet
        packet = w.recv()
        if packet.src_addr == local_ip and packet.dst_addr == dest_ip:
            packet.ipv4.tos = dscp_value                # Set DSCP value
            packet.ipv4.ident = 0x0000                  # Set IP identification field to 0x0000   
            packet.ipv4.mf = False                      # Clear the 'more fragments' flag
            packet.ipv4.df = True                       # Set the 'don't fragment' flag            
            w.send(packet)                              # Send the packet on
    return            

def convert_wav_to_pcma(input_wav_file, output_pcma_file):
    command = [
        'ffmpeg',
        '-y',                   # Overwrite output files without asking
        '-i', input_wav_file,
        '-ar', '8000',          # Set the audio sample rate to 8000 Hz
        '-ac', '1',             # Set the audio channels to 1 (mono)
        '-f', 'alaw',           # Specify the format explicitly
        output_pcma_file
    ]
    
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(output_pcma_file, 'rb') as f:
        pcma_data = f.read()    
    return pcma_data      
                      
def send_audio_message(wav_file_name, pcma_file_name, local_ip, local_port, remote_ip, remote_port):
    # Create an RTP socket for sending audio
    print(f"Convert WAV file ({wav_file_name}) to PCMA data and send from {local_ip}:{local_port} to {remote_ip}:{remote_port}")
    pcma_data = convert_wav_to_pcma(wav_file_name, pcma_file_name)
    rtpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rtpsock.bind((local_ip, local_port))     
        
    sequence_number = random.randint(0, 65535)
    timestamp = random.randint(0, 4294967295)
    ssrc = np.random.randint(0, 0xFFFFFFFF + 1, dtype=np.uint32)
    payloadType = 0x88          # Payload type 0x88 (PCMA), Marker bit set to 1 for the first packet
    
    next_send_time = time.time()
    for i in range(0, len(pcma_data), 160):
        rtp_data = pcma_data[i:i+160]
        send_rtp_packet(rtpsock, rtp_data, local_ip, local_port, remote_ip, remote_port, sequence_number, timestamp, ssrc, payloadType)
        payloadType = 0x08      # Payload type 0x08 (PCMA), Marker bit set to 0 for all remaining packets
        sequence_number += 1    # Increment sequence number
        timestamp += 160        # 160 samples per 20ms at 8kHz   
        
        # Adjust for any drift in timing (20msec per sample)
        next_send_time += 0.02
        sleep_time = next_send_time - time.time()
        if sleep_time > 0:
            time.sleep(sleep_time)
        
    rtpsock.close()   
    
if __name__ == "__main__":
    result, sock, proxy_server_ip, call_id, tag, contact_uuid, proxy_server = registerSIP()
    if (result == True):
        time.sleep(1)
        print(f"Initiate a phone call from {CALLER_PHONE_NUMBER} to {REMOTE_PHONE_NUMBER}...") 
        initiatePhoneCall(sock, proxy_server_ip, call_id, tag, contact_uuid, proxy_server)