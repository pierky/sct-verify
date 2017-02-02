#!/usr/bin/env python

# Signed Certificate Timestamp TLS extension verifier  
# Copyright (c) 2015 Pier Carlo Chiodi - http://www.pierky.com
#
# https://github.com/pierky/sct-verify

import sys
import subprocess
import base64
import struct
import os

try:
  OPENSSL_PATH = os.environ["OPENSSL_PATH"]
except:
  OPENSSL_PATH = "openssl"

LOGS = [
    { "Name": "Aviator - FROZEN",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1J\n"
    "YP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=" },

    { "Name": "Digicert Log",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCF\n"
    "RkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=" },

    { "Name": "Pilot",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHT\n"
    "DM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=" },

    { "Name": "Icarus",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlU\n"
    "aESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=" },

    { "Name": "Rocketeer",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1\n"
    "aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=" },

    { "Name": "Skydiver",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2x\n"
    "zb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=" },

    { "Name": "Comodo Dodo",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELPXCMfVjQ2oWSgrewu4fIW4Sfh3lco90CwKZ061p\n"
    "vAI1eflh6c8ACE90pKM0muBDHCN+j0HV7scco4KKQPqq4A==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "23b9raxl59CVCIhuIVm9i5A1L1/q0+PcXiLrNQrMe5g=" },

    { "Name": "Symantec log",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY\n"
    "4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvsw=" },

    { "Name": "Venafi log",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OC\n"
    "dpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym\n"
    "97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWt\n"
    "gnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB\n"
    "8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauC\n"
    "Fx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5\n"
    "wQIDAQAB\n"
    "-----END PUBLIC KEY-----",
    "LogID": "rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0=" },

    { "Name": "WoSign log",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzBGIey1my66PTTBmJxklIpMhRrQv\n"
    "AdPG+SvVyLpzmwai8IoCnNBrRhgwhbrpJIsO0VtwKAx+8TpFf1rzgkJgMQ==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "QbLcLonmPOSvG6e7Kb9oxt7m+fHMBH4w3/rjs7olkmM=" },

    { "Name": "Symantec Vega",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6pWeAv/u8TNtS4e8zf0ZF2L/lNPQ\n"
    "WQc/Ai0ckP7IRzA78d0NuBEMXR2G3avTK0Zm+25ltzv9WWis36b4ztIYTQ==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "vHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKU=" },

    { "Name": "CNNIC",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv7UIYZopMgTTJWPp2IXh\n"
    "huAf1l6a9zM7gBvntj5fLaFm9pVKhKYhVnno94XuXeN8EsDgiSIJIj66FpUGvai5\n"
    "samyetZhLocRuXhAiXXbDNyQ4KR51tVebtEq2zT0mT9liTtGwiksFQccyUsaVPhs\n"
    "Hq9gJ2IKZdWauVA2Fm5x9h8B9xKn/L/2IaMpkIYtd967TNTP/dLPgixN1PLCLayp\n"
    "vurDGSVDsuWabA3FHKWL9z8wr7kBkbdpEhLlg2H+NAC+9nGKx+tQkuhZ/hWR65aX\n"
    "+CNUPy2OB9/u2rNPyDydb988LENXoUcMkQT0dU3aiYGkFAY0uZjD2vH97TM20xYt\n"
    "NQIDAQAB\n"
    "-----END PUBLIC KEY-----",
    "LogID": "pXesnO11SN2PAltnokEInfhuD0duwgPC7L7bGF8oJjg=" },

    { "Name": "StartSSL",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESPNZ8/YFGNPbsu1Gfs/IEbVXsajW\n"
    "TOaft0oaFIZDqUiwy1o/PErK38SCFFWa+PeOQFXc9NKv6nV0+05/YIYuUQ==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "NLtq1sPfnAPuqKSZ/3iRSGydXlysktAfe/0bzhnbSO8=" },

    ]

if len( sys.argv ) <= 1:
    print( "Missing hostname argument." )
    print( "Usage: ./sct-verify hostname" )
    print( "" )
    print( "Example:" )
    print( "  ./sct-verify sni.velox.ch" )
    print( "" )
    print( "Known hosts implementing SCT TLS Extensions:" )
    print( " - blog.pierky.com" )
    print( " - sni.velox.ch" )
    print( " - ritter.vg" )
    quit()

HostName = sys.argv[1]

Args = [ OPENSSL_PATH ]
Args.extend( [ "s_client", "-serverinfo", "18", "-connect", "%s:443" % HostName, "-servername", HostName ])

OpenSSL= subprocess.Popen( Args, stdin=open('/dev/null', 'r'), stdout=subprocess.PIPE, stderr=subprocess.PIPE )
OpenSSL_stdout, OpenSSL_stderr = OpenSSL.communicate()
OpenSSL_exitcode = OpenSSL.wait()

if OpenSSL_exitcode != 0:
    print("OpenSSL can't connect to %s" % HostName)
    print(OpenSSL_stderr)
    quit()

ServerInfo18 = ""
ServerInfo18_Add = False
EECert = ""
EECert_Add = False
for L in OpenSSL_stdout.split('\n'):
    if L == "-----BEGIN SERVERINFO FOR EXTENSION 18-----":
        ServerInfo18_Add = True
    elif L == "-----END SERVERINFO FOR EXTENSION 18-----":
        ServerInfo18_Add = False
    elif L == "-----BEGIN CERTIFICATE-----":
        EECert_Add = True
    elif L == "-----END CERTIFICATE-----":
        EECert_Add = False
    elif ServerInfo18_Add:
        if ServerInfo18:
            ServerInfo18 = ServerInfo18 + '\n'
        ServerInfo18 = ServerInfo18 + L
    elif EECert_Add:
        if EECert:
            EECert = EECert + '\n'
        EECert = EECert + L

EECertDER = base64.b64decode( EECert )

Data = base64.b64decode( ServerInfo18 )
DataLen = len(Data)

if DataLen == 0:
    print("No TLS extensions found.")
    quit()

def ToHex( v ):
    if type(v) is int or type(v) is long:
        return hex(v)
    else:
        return ":".join("{:02x}".format(ord(c)) for c in v)

def Read( buf, offset, format ):
    Values = struct.unpack_from( format, buf, offset )
    NewOffset = offset + struct.calcsize( format )

    Ret = ()
    Ret = Ret + ( NewOffset, )
    Ret = Ret + Values
    return Ret

def ReadSCT( SCT ):
    print("===========================================================")
    Offset = 0

    Offset, SCTVersion = Read( SCT, Offset, "!B" )

    Offset, SCTLogID = Read( SCT, Offset, "!32s" )
    Base64LogID = base64.b64encode( SCTLogID )

    Offset, SCTTimestamp = Read( SCT, Offset, "!Q" )

    Offset, SCTExtensionsLen = Read( SCT, Offset, "!H" )

    #FIXME
    if SCTExtensionsLen > 0:
        print("Extensions length > 0; not implemented")
        return

    Offset, SCTSignatureAlgHash = Read( SCT, Offset, "!B" )
    Offset, SCTSignatureAlgSign = Read( SCT, Offset, "!B" )

    Offset, SCTSignatureLen = Read( SCT, Offset, "!H" )
    Offset, SCTSignature = Read( SCT, Offset, "!%ss" % SCTSignatureLen )

    # print SCT information

    print( "Version   : %s" % ToHex( SCTVersion ) )
    SCTLogID1, SCTLogID2 = struct.unpack( "!16s16s", SCTLogID )
    print( "LogID     : %s" % ToHex( SCTLogID1 ) )
    print( "            %s" % ToHex( SCTLogID2 ) )
    print( "LogID b64 : %s" % Base64LogID )
    print( "Timestamp : %s (%s)" % ( SCTTimestamp, ToHex( SCTTimestamp ) ) )
    print( "Extensions: %s (%s)" % ( SCTExtensionsLen, ToHex( SCTExtensionsLen )) )
    print( "Algorithms: %s/%s (hash/sign)" % ( ToHex( SCTSignatureAlgHash ), ToHex ( SCTSignatureAlgSign ) )) 

    SigOffset = 0
    while SigOffset < len( SCTSignature ):
        if len( SCTSignature ) - SigOffset > 16:
            SigBytesToRead = 16
        else:
            SigBytesToRead = len( SCTSignature ) - SigOffset
        SigBytes = struct.unpack_from( "!%ss" % SigBytesToRead, SCTSignature, SigOffset )[0]

        if SigOffset == 0:
            print( "Signature : %s" % ToHex( SigBytes ) )
        else:
            print( "            %s" % ToHex( SigBytes ) )
    
        SigOffset = SigOffset + SigBytesToRead

    # look for signing log and its key

    PubKey = None
    for Log in LOGS:
        if Log["LogID"] == Base64LogID:
            print( "Log found : %s" % Log["Name"])
            PubKey = Log["Key"]

    if not PubKey:
        print("Log not found")
        return

    # signed data

    # 1 version
    # 1 signature_type
    # 8 timestamp
    # 2 entry_type
    # 3 DER lenght
    # x DER
    # 2 extensions length

    EECertDERLen = len( EECertDER )
    _, EECertDERLen1, EECertDERLen2, EECertDERLen3 = struct.unpack( "!4B", struct.pack( "!I", EECertDERLen ) )
    
    Data = struct.pack("!BBQhBBB%ssh" % len( EECertDER ), SCTVersion, 0, SCTTimestamp, 0, EECertDERLen1, EECertDERLen2, EECertDERLen3, EECertDER, SCTExtensionsLen )

    File = open("tmp-signeddata.bin", "wb")
    File.write( Data )
    File.close()

    File = open("tmp-pubkey.pem", "w")
    File.write( PubKey )
    File.close()

    File = open("tmp-signature.bin", "wb")
    File.write( SCTSignature )
    File.close()

    Args = [ OPENSSL_PATH ] 
    Args.extend( [ "dgst", "-sha256", "-verify", "tmp-pubkey.pem", "-signature", "tmp-signature.bin", "tmp-signeddata.bin" ] )

    OpenSSL= subprocess.Popen( Args, stdin=open('/dev/null', 'r'), stdout=subprocess.PIPE, stderr=subprocess.PIPE )
    OpenSSL_stdout, OpenSSL_stderr = OpenSSL.communicate()
    OpenSSL_exitcode = OpenSSL.wait()

    if OpenSSL_exitcode == 0:
        print( "Result    : %s" % OpenSSL_stdout )
    else:
        print( "OpenSSL error - Exit code %d" % OpenSSL_exitcode )
        print( OpenSSL_stderr )

Offset = 0
Offset, TLS_ExtensionType, TLS_ExtensionLen = Read( Data, Offset, "!HH" )
Offset, SignedCertificateTimestampListLen = Read( Data, Offset, "!H" )

while Offset < DataLen:
    Offset, SCTLen = Read( Data, Offset, "!H" )
    Offset, SCT = Read( Data, Offset, "!%ss" % SCTLen )
    ReadSCT( SCT )
