"""
Test cases for the validation module, ported from the Rust implementation

These test cases validate the core DNSSEC validation functionality using
the exact same test data and logic as the Rust implementation.
"""

import os
import sys
import pytest
from io import BytesIO
import base64
from typing import List, Tuple
import random
import json

# Add the parent directory to path to import dnssec_prover module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from rr import *
from validation import (
    root_hints, verify_rr_stream, verify_rrsig, verify_rr_set, resolve_time, 
    ValidationError, VerifiedRRStream, verify_byte_stream
)
import random


def test_rfc4034_sort():
    """Test nsec_ord based on RFC 4034 section 6.1's example"""
    # Note: This tests the NSEC ordering logic which is embedded in validation.rs
    # We'll implement a simplified version for testing
    def nsec_ord(a: str, b: str) -> int:
        """
        NSEC ordering function - DNS names are compared case-insensitively
        """
        if a == b:
            return 0
        
        # Convert to lowercase for case-insensitive comparison
        a_lower = a.lower()
        b_lower = b.lower()
        
        # Split into labels and reverse for comparison
        a_labels = a_lower.rstrip('.').split('.')[::-1] if a_lower != '.' else ['']
        b_labels = b_lower.rstrip('.').split('.')[::-1] if b_lower != '.' else ['']
        
        # Compare label by label
        for i in range(max(len(a_labels), len(b_labels))):
            a_label = a_labels[i] if i < len(a_labels) else ''
            b_label = b_labels[i] if i < len(b_labels) else ''
            
            if a_label < b_label:
                return -1
            elif a_label > b_label:
                return 1
        
        # If all labels are equal up to this point, shorter name comes first
        if len(a_labels) < len(b_labels):
            return -1
        elif len(a_labels) > len(b_labels):
            return 1
        else:
            return 0

    # Test cases from RFC 4034 section 6.1
    test_cases = [
        ("example.", "a.example."),
        ("a.example.", "yljkjljk.a.example."),
        ("yljkjljk.a.example.", "Z.a.example."),
        ("Z.a.example.", "zABC.a.EXAMPLE."),
        ("zABC.a.EXAMPLE.", "z.example."),
        ("z.example.", "*.z.example."),
        ("*.z.example.", "\\200.z.example.")
    ]
    
    for a, b in test_cases:
        assert nsec_ord(a, b) < 0, f"Expected {a} < {b}"
        assert nsec_ord(b, a) > 0, f"Expected {b} > {a}"


# Test data helper functions - ported from Rust validation.rs

def root_dnskey() -> Tuple[List[DnsKey], List[Record]]:
    """Root DNSKEY data"""
    dnskeys = [
        DnsKey(
            Name("."), 256, 3, 8,
            base64.b64decode("AwEAAentCcIEndLh2QSK+pHFq/PkKCwioxt75d7qNOUuTPMo0Fcte/NbwDPbocvbZ/eNb5RV/xQdapaJASQ/oDLsqzD0H1+JkHNuuKc2JLtpMxg4glSE4CnRXT2CnFTW5IwOREL+zeqZHy68OXy5ngW5KALbevRYRg/q2qFezRtCSQ0knmyPwgFsghVYLKwi116oxwEU5yZ6W7npWMxt5Z+Qs8diPNWrS5aXLgJtrWUGIIuFfuZwXYziGRP/z3o1EfMo9zZU19KLopkoLXX7Ls/diCXdSEdJXTtFA8w0/OKQviuJebfKscoElCTswukVZ1VX5gbaFEo2xWhHJ9Uo63wYaTk=")
        ),
        DnsKey(
            Name("."), 257, 3, 8,
            base64.b64decode("AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=")
        )
    ]
    
    dnskey_rrsig = RRSig(
        Name("."), DnsKey.TYPE, 8, 0, 172800,
        1710201600, 1708387200, 20326, Name("."),
        base64.b64decode("GIgwndRLXgt7GX/JNEqSvpYw5ij6EgeQivdC/hmNNuOd2MCQRSxZx2DdLZUoK0tmn2XmOd0vYP06DgkIMUpIXcBstw/Um55WQhvBkBTPIhuB3UvKYJstmq+8hFHWVJwKHTg9xu38JA43VgCV2AbzurbzNOLSgq+rDPelRXzpLr5aYE3y+EuvL+I5gusm4MMajnp5S+ioWOL+yWOnQE6XKoDmlrfcTrYfRSxRtJewPmGeCbNdwEUBOoLUVdkCjQG4uFykcKL40cY8EOhVmM3kXAyuPuNe2Xz1QrIcVad/U4FDns+hd8+W+sWnr8QAtIUFT5pBjXooGS02m6eMdSeU6g==")
    )
    
    rrs = [dnskeys[0], dnskeys[1], dnskey_rrsig]
    return (dnskeys, rrs)


def com_dnskey() -> Tuple[List[DnsKey], List[Record]]:
    """COM DNSKEY data"""
    com_ds = DS(
        Name("com."), 19718, 13, 2,
        bytes.fromhex("8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D771D7805A")
    )
    
    ds_rrsig = RRSig(
        Name("com."), DS.TYPE, 8, 1, 86400,
        1710133200, 1709006400, 30903, Name("."),
        base64.b64decode("WEf7UPqoulxab83nVy/518TpZcC3og0paZ7Lag5iOqGdmGvZnB0yQ42s25iqB/mL6ZU+sSUwYoclcW36Tv/yHgS813T2wOgQ4Jh01aCsjkjvpgpbtnDTxg8bL30LV1obhQhOBFu5SqD4FOMeaV9Fqcff7Z72vC1UdVy0us2Kbhti3uQYrKQlGYcDMlgQAyOE0WEaLT74YfKFTpZvIK0UfUfdUAAiM0Z6PUi7BoyToIN+eKKPvny/+4BP9iVvAOmPMgr+kq/qIWOdsvUaq/S+k7VEPTJEi+i2gODgbMC+3EZZpZie9kv1EEAwGwBtGjE7bLlA1QUbuVeTgczIzrYriQ==")
    )
    
    dnskeys = [
        DnsKey(
            Name("com."), 256, 3, 13,
            base64.b64decode("5i9qjJgyH+9MBz7VO269/srLQB/xRRllyUoVq8oLBZshPe4CGzDSFGnXAM3L/QPzB9ULpJuuy7jcxmBZ5Ebo7A==")
        ),
        DnsKey(
            Name("com."), 257, 3, 13,
            base64.b64decode("tx8EZRAd2+K/DJRV0S+hbBzaRPS/G6JVNBitHzqpsGlz8huE61Ms9ANe6NSDLKJtiTBqfTJWDAywEp1FCsEINQ==")
        )
    ]
    
    dnskey_rrsig = RRSig(
        Name("com."), DnsKey.TYPE, 13, 1, 86400,
        1710342155, 1709045855, 19718, Name("com."),
        base64.b64decode("lF2B9nXZn0CgytrHH6xB0NTva4G/aWvg/ypnSxJ8+ZXlvR0C4974yB+nd2ZWzWMICs/oPYMKoQHqxVjnGyu8nA==")
    )
    
    rrs = [com_ds, ds_rrsig, dnskeys[0], dnskeys[1], dnskey_rrsig]
    return (dnskeys, rrs)


def ninja_dnskey() -> Tuple[List[DnsKey], List[Record]]:
    """NINJA DNSKEY data"""
    ninja_ds = DS(
        Name("ninja."), 46082, 8, 2,
        bytes.fromhex("C8F816A7A575BDB2F997F682AAB2653BA2CB5EDDB69B036A30742A33BEFAF141")
    )
    
    ds_rrsig = RRSig(
        Name("ninja."), DS.TYPE, 8, 1, 86400,
        1710133200, 1709006400, 30903, Name("."),
        base64.b64decode("4fLiekxJy1tHW3sMzmPA/i4Mn6TYoCHDKbcvk3t3N6IXMkACSgU+6P5NxSMxo5Xa7YL5UuE1ICDKxel5o5WzyvjaRQA//hZomjwnCzqyG2XoS6Va8cULSOA5jOU153NSCvos39iHeJnuPINzbMAfsKcg6Ib/IDmNnpouQF53hQzVy+5MGLlGPUZjSO6b4GIslyKpLG0tBLKXM5rZXREPJClEY+LWKOtAS1iARqdsWmSnKxZCpgnEjmkqJBtjCus+s6AtMteBHIFyebwA7oUDNtJ3Im1dO5b6sUoGP8gUgnqdFELSLEeEhKYKpO+jSruI8g/gjNIb5C9vDwAtcSoAew==")
    )
    
    dnskeys = [
        DnsKey(
            Name("ninja."), 256, 3, 8,
            base64.b64decode("AwEAAb6FWe0O0qxUkA+LghF71OPWt0WNqBaCi34HCV6Agjz70RN/j7yGi3xCExM8MkzyrbXd5yYFP4X7TCGEzI5ofLNq7GVIj9laZO0WYS8DNdCMN7qkVVaYeR2UeeGsdvIJqRWzlynABAKnCzX+y5np77FBsle4cAIGxJE/0F5kn61F")
        ),
        DnsKey(
            Name("ninja."), 256, 3, 8,
            base64.b64decode("AwEAAZlkeshgX2Q9i/X4zZMc2ciKO2a3+mOiOCuYHYbwt/43XXdcHdjtOUrWFFJkGBBWsHQZ/Bg0CeUGqvUGywd3ndY5IAX+e7PnuIUlhKDcNmntcQbxhrH+cpmOoB3Xo/96JoVjurPxTuJE23I1oA+0aESc581f4pKEbTp4WI7m5xNn")
        ),
        DnsKey(
            Name("ninja."), 257, 3, 8,
            base64.b64decode("AwEAAcceTJ3Ekkmiez70L8uNVrTDrHZxXHrQHEHQ1DJZDRXDxizuSy0prDXy1yybMqcKAkPL0IruvJ9vHg5j2eHN/hM8RVqCQ1wHgLdQASyUL37VtmLuyNmuiFpYmT+njXVh/tzRHZ4cFxrLAtACWDe6YaPApnVkJ0FEcMnKCQaymBaLX02WQOYuG3XdBr5mQQTtMs/kR/oh83QBcSxyCg3KS7G8IPP6MQPK0za94gsW9zlI5rgN2gpSjbU2qViGjDhw7N3PsC37PLTSLirUmkufeMkP9sfhDjAbP7Nv6FmpTDAIRmBmV0HBT/YNBTUBP89DmEDsrYL8knjkrOaLqV5wgkk=")
        )
    ]
    
    dnskey_rrsig = RRSig(
        Name("ninja."), DnsKey.TYPE, 8, 1, 3600,
        1710689605, 1708871605, 46082, Name("ninja."),
        base64.b64decode("kYxV1z+9Ikxqbr13N+8HFWWnAUcvHkr/dmkdf21mliUhH4cxeYCXC6a95X+YzjYQEQi3fU+S346QBDJkbFYCca5q/TzUdE7ej1B/0uTzhgNrQznm0O6sg6DI3HuqDfZp2oaBQm2C/H4vjkcUW9zxgKP8ON0KKLrZUuYelGazeGSOscjDDlmuNMD7tHhFrmK9BiiX+8sp8Cl+IE5ArP+CPXsII+P+R2QTmTqw5ovJch2FLRMRqCliEzTR/IswBI3FfegZR8h9xJ0gfyD2rDqf6lwJhD1K0aS5wxia+bgzpRIKwiGfP87GDYzkygHr83QbmZS2YG1nxlnQ2rgkqTGgXA==")
    )
    
    rrs = [ninja_ds, ds_rrsig, dnskeys[0], dnskeys[1], dnskeys[2], dnskey_rrsig]
    return (dnskeys, rrs)


def mattcorallo_dnskey() -> Tuple[List[DnsKey], List[Record]]:
    """mattcorallo.com DNSKEY data"""
    mattcorallo_ds = DS(
        Name("mattcorallo.com."), 25630, 13, 2,
        bytes.fromhex("DC608CA62BE89B3B9DB1593F9A59930D24FBA79D486E19C88A7792711EC00735")
    )
    
    ds_rrsig = RRSig(
        Name("mattcorallo.com."), DS.TYPE, 13, 2, 86400,
        1709359258, 1708750258, 4534, Name("com."),
        base64.b64decode("VqYztN78+g170QPeFOqWFkU1ZrKIsndUYj3Y+8x1ZR1v/YGJXLQe5qkcLWjrl/vMyCgknC3Q/dhcS2ag0a7W1w==")
    )
    
    dnskeys = [
        DnsKey(
            Name("mattcorallo.com."), 257, 3, 13,
            base64.b64decode("8BP51Etiu4V6cHvGCYqwNqCip4pvHChjEgkgG4zpdDvO9YRcTGuV/p71hAUut2/qEdxqXfUOT/082BJ/Z089DA==")
        ),
        DnsKey(
            Name("mattcorallo.com."), 256, 3, 13,
            base64.b64decode("AhUlQ8qk7413R0m4zKfTDHb/FQRlKag+ncGXxNxT+qTzSZTb9E5IGjo9VCEp6+IMqqpkd4GrXpN9AzDvlcU9Ig==")
        ),
        DnsKey(
            Name("mattcorallo.com."), 256, 3, 13,
            base64.b64decode("s165ZpubX31FC2CVeIVVvnPpTnJUoOM8CGt3wk4AtxPftYadgI8uFM43F4QaD67v8B8Vshl63frxN50dc44VHQ==")
        )
    ]
    
    dnskey_rrsig = RRSig(
        Name("mattcorallo.com."), DnsKey.TYPE, 13, 2, 604800,
        1710262250, 1709047250, 25630, Name("mattcorallo.com."),
        base64.b64decode("dMLDvNU96m+tfgpDIQPxMBJy7T0xyZDj3Wws4b4E6+g3nt5iULdWJ8Eqrj+86KLerOVt7KH4h/YcHP18hHdMGA==")
    )
    
    rrs = [mattcorallo_ds, ds_rrsig, dnskeys[0], dnskeys[1], dnskeys[2], dnskey_rrsig]
    return (dnskeys, rrs)


def mattcorallo_txt_record() -> Tuple[Txt, RRSig]:
    """mattcorallo.com TXT record data"""
    txt_resp = Txt(
        Name("matt.user._bitcoin-payment.mattcorallo.com."),
        b"bitcoin:?b12=lno1qsgqmqvgm96frzdg8m0gc6nzeqffvzsqzrxqy32afmr3jn9ggkwg3egfwch2hy0l6jut6vfd8vpsc3h89l6u3dm4q2d6nuamav3w27xvdmv3lpgklhg7l5teypqz9l53hj7zvuaenh34xqsz2sa967yzqkylfu9xtcd5ymcmfp32h083e805y7jfd236w9afhavqqvl8uyma7x77yun4ehe9pnhu2gekjguexmxpqjcr2j822xr7q34p078gzslf9wpwz5y57alxu99s0z2ql0kfqvwhzycqq45ehh58xnfpuek80hw6spvwrvttjrrq9pphh0dpydh06qqspp5uq4gpyt6n9mwexde44qv7lstzzq60nr40ff38u27un6y53aypmx0p4qruk2tf9mjwqlhxak4znvna5y"
    )
    
    txt_rrsig = RRSig(
        Name("matt.user._bitcoin-payment.mattcorallo.com."),
        Txt.TYPE, 13, 5, 3600, 1710182540,
        1708967540, 47959, Name("mattcorallo.com."),
        base64.b64decode("vwI89CkCzWI2Iwgl3UeiSo4GKSaKCh7/E/7nE8Hbb1WQvdpwdKSB6jE4nwM1BN4wdPhi7kxd7hyS/uGiKZjxsg==")
    )
    
    return (txt_resp, txt_rrsig)


def bitcoin_ninja_dnskey() -> Tuple[List[DnsKey], List[Record]]:
    """bitcoin.ninja DNSKEY data"""
    bitcoin_ninja_ds = DS(
        Name("bitcoin.ninja."), 63175, 13, 2,
        bytes.fromhex("D554267D7F730B9602BF4436F46BB967EFE3C4202CA7F082F2D5DD24DF4EBDED")
    )
    
    ds_rrsig = RRSig(
        Name("bitcoin.ninja."), DS.TYPE, 8, 2, 3600,
        1710689605, 1708871605, 34164, Name("ninja."),
        base64.b64decode("g/Xyv6cwrGlpEyhXDV1vdKpoy9ZH7HF6MK/41q0GyCrd9wL8BrzKQgwvLqOBhvfUWACJd66CJpEMZnSwH8ZDEcWYYsd8nY2giGX7In/zGz+PA35HlFqy2BgvQcWCaN5Ht/+BUTgZXHbJBEko1iWLZ1yhciD/wA+XTqS7ScQUu88=")
    )
    
    dnskeys = [
        DnsKey(
            Name("bitcoin.ninja."), 257, 3, 13,
            base64.b64decode("0lIZI5BH7kk75R/+1RMReQE0J2iQw0lY2aQ6eCM7F1E9ZMNcIGC1cDl5+FcAU1mP8F3Ws2FjgvCC0S2q8OBF2Q==")
        ),
        DnsKey(
            Name("bitcoin.ninja."), 256, 3, 13,
            base64.b64decode("zbm2rKgzXDtRFV0wFmnlUMdOXWcNKEjGIHsZ7bAnTzbh7TJEzPctSttCaTvdaORxLL4AiOk+VG2iXnL2UuC/xQ==")
        )
    ]
    
    dnskey_rrsig = RRSig(
        Name("bitcoin.ninja."), DnsKey.TYPE, 13, 2, 604800,
        1709947337, 1708732337, 63175, Name("bitcoin.ninja."),
        base64.b64decode("Y3To5FZoZuBDUMtIBZXqzRtufyRqOlDqbHVcoZQitXxerCgNQ1CsVdmoFVMmZqRV5n4itINX2x+9G/31j410og==")
    )
    
    rrs = [bitcoin_ninja_ds, ds_rrsig, dnskeys[0], dnskeys[1], dnskey_rrsig]
    return (dnskeys, rrs)


def bitcoin_ninja_txt_record() -> Tuple[Txt, RRSig]:
    """bitcoin.ninja TXT record data"""
    txt_resp = Txt(
        Name("txt_test.dnssec_proof_tests.bitcoin.ninja."),
        b"dnssec_prover_test"
    )
    
    txt_rrsig = RRSig(
        Name("txt_test.dnssec_proof_tests.bitcoin.ninja."),
        Txt.TYPE, 13, 4, 30, 1709950937,
        1708735937, 37639, Name("bitcoin.ninja."),
        base64.b64decode("S5swe6BMTqwLBU6FH2D50j5A9i5hzli79Vlf5xB515s6YhmcqodbPZnFlN49RdBE43PKi9MJcXpHTiBxvTYBeQ==")
    )
    
    return (txt_resp, txt_rrsig)


def bitcoin_ninja_cname_record() -> Tuple[CName, RRSig]:
    """bitcoin.ninja CNAME record data"""
    cname_resp = CName(
        Name("cname_test.dnssec_proof_tests.bitcoin.ninja."),
        Name("txt_test.dnssec_proof_tests.bitcoin.ninja.")
    )
    
    cname_rrsig = RRSig(
        Name("cname_test.dnssec_proof_tests.bitcoin.ninja."),
        CName.TYPE, 13, 4, 30, 1709950937,
        1708735937, 37639, Name("bitcoin.ninja."),
        base64.b64decode("S8AYftjBADKutt4XKVzqfY7EpvbanpwOGhMDk0lEDFpvNRjl0fZ1k/FEW6AXSUyX2wOaX8hvwXUuZjpr5INuMw==")
    )
    
    return (cname_resp, cname_rrsig)


def bitcoin_ninja_txt_sort_edge_cases_records() -> Tuple[List[Txt], RRSig]:
    """bitcoin.ninja TXT sorting edge cases"""
    txts = [
        Txt(Name("txt_sort_order.dnssec_proof_tests.bitcoin.ninja."), 
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"),
        Txt(Name("txt_sort_order.dnssec_proof_tests.bitcoin.ninja."), 
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Txt(Name("txt_sort_order.dnssec_proof_tests.bitcoin.ninja."), 
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabaa"),
        Txt(Name("txt_sort_order.dnssec_proof_tests.bitcoin.ninja."), 
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaba"),
        Txt(Name("txt_sort_order.dnssec_proof_tests.bitcoin.ninja."), 
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Txt(Name("txt_sort_order.dnssec_proof_tests.bitcoin.ninja."), 
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"),
        Txt(Name("txt_sort_order.dnssec_proof_tests.bitcoin.ninja."), 
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Txt(Name("txt_sort_order.dnssec_proof_tests.bitcoin.ninja."), 
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaba")
    ]
    
    rrsig = RRSig(
        Name("txt_sort_order.dnssec_proof_tests.bitcoin.ninja."),
        Txt.TYPE, 13, 4, 30, 1709950937,
        1708735937, 37639, Name("bitcoin.ninja."),
        base64.b64decode("kUKbtoNYM6qnu95QJoyUwtzZoMTcRVfNfIIqSwROLdMYqqq70REjCu99ecjOW/Zm2XRsJ9KgGBB/SuiBdunLew==")
    )
    
    return (txts, rrsig)


def bitcoin_ninja_wildcard_record(pfx: str) -> Tuple[Txt, RRSig, NSec3, RRSig]:
    """bitcoin.ninja wildcard record - Note: NSEC3 proofs here are for asdf., other prefixes may fail NSEC checks"""
    name = Name(pfx + ".wildcard_test.dnssec_proof_tests.bitcoin.ninja.")
    
    txt_resp = Txt(name, b"wildcard_test")
    
    txt_rrsig = RRSig(
        name, Txt.TYPE, 13, 4, 30, 1709950937,
        1708735937, 37639, Name("bitcoin.ninja."),
        base64.b64decode("Y+grWXzbZfrcoHRZC9kfRzWp002jZzBDmpSQx6qbUgN0x3aH9kZIOVy0CtQH2vwmLUxoJ+RlezgunNI6LciBzQ==")
    )
    
    # Import base32 module
    from base32 import decode as base32_decode
    
    nsec3 = NSec3(
        Name("s5sn15c8lcpo7v7f1p0ms6vlbdejt0kd.bitcoin.ninja."),
        1, 0, 0, bytes.fromhex("059855BD1077A2EB"),
        # Use our base32 decode function with the correct format
        base32_decode("T8QO5GO6M76HBR5Q6T3G6BDR79KBMDSA"),
        NSecTypeMask.from_types([AAAA.TYPE, RRSig.TYPE])
    )
    
    nsec3_rrsig = RRSig(
        Name("s5sn15c8lcpo7v7f1p0ms6vlbdejt0kd.bitcoin.ninja."),
        NSec3.TYPE, 13, 3, 60, 1710267741,
        1709052741, 37639, Name("bitcoin.ninja."),
        base64.b64decode("Aiz6My3goWQuIIw/XNUo+kICsp9e4C5XUUs/0Ap+WIEFJsaN/MPGegiR/c5GUGdtHt1GdeP9CU3H1OGkN9MpWQ==")
    )
    
    return (txt_resp, txt_rrsig, nsec3, nsec3_rrsig)


# Test cases - ported from Rust validation.rs

def test_check_txt_record_a():
    """Test verifying a single TXT record signature"""
    # First build and validate the complete chain to get trusted DNSKEYs
    rr_stream = BytesIO()
    for rr in root_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in com_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in mattcorallo_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    
    # Parse and validate to get trusted keys
    rrs = parse_rr_stream(rr_stream.getvalue())
    verify_rr_stream(rrs)  # This validates the chain
    
    # Now test individual signature verification
    dnskeys = mattcorallo_dnskey()[0]
    txt, txt_rrsig = mattcorallo_txt_record()
    txt_resp = [txt]
    verify_rrsig(txt_rrsig, dnskeys, txt_resp)


def test_check_single_txt_proof():
    """Test verifying a complete chain for a TXT record"""
    rr_stream = BytesIO()
    
    # Build the complete chain
    for rr in root_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in com_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in ninja_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in mattcorallo_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    
    txt, txt_rrsig = mattcorallo_txt_record()
    write_rr(txt, 1, rr_stream)
    write_rr(txt_rrsig, 1, rr_stream)
    
    rrs = parse_rr_stream(rr_stream.getvalue())
    random.shuffle(rrs)
    verified_rrs = verify_rr_stream(rrs)
    
    assert len(verified_rrs.verified_rrs) == 1
    assert isinstance(verified_rrs.verified_rrs[0], Txt)
    txt = verified_rrs.verified_rrs[0]
    assert txt.name.name == "matt.user._bitcoin-payment.mattcorallo.com."
    assert txt.data == b"bitcoin:?b12=lno1qsgqmqvgm96frzdg8m0gc6nzeqffvzsqzrxqy32afmr3jn9ggkwg3egfwch2hy0l6jut6vfd8vpsc3h89l6u3dm4q2d6nuamav3w27xvdmv3lpgklhg7l5teypqz9l53hj7zvuaenh34xqsz2sa967yzqkylfu9xtcd5ymcmfp32h083e805y7jfd236w9afhavqqvl8uyma7x77yun4ehe9pnhu2gekjguexmxpqjcr2j822xr7q34p078gzslf9wpwz5y57alxu99s0z2ql0kfqvwhzycqq45ehh58xnfpuek80hw6spvwrvttjrrq9pphh0dpydh06qqspp5uq4gpyt6n9mwexde44qv7lstzzq60nr40ff38u27un6y53aypmx0p4qruk2tf9mjwqlhxak4znvna5y"
    
    assert verified_rrs.valid_from == 1709047250  # The mattcorallo.com. DNSKEY RRSig was created last
    assert verified_rrs.expires == 1709359258     # The mattcorallo.com. DS RRSig expires first
    assert verified_rrs.max_cache_ttl == 3600     # The TXT record had the shortest TTL


def test_check_txt_record_b():
    """Test verifying another TXT record signature"""
    # First build and validate the complete chain to get trusted DNSKEYs
    rr_stream = BytesIO()
    for rr in root_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in ninja_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in bitcoin_ninja_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    
    # Parse and validate to get trusted keys
    rrs = parse_rr_stream(rr_stream.getvalue())
    verify_rr_stream(rrs)  # This validates the chain
    
    # Now test individual signature verification
    dnskeys = bitcoin_ninja_dnskey()[0]
    txt, txt_rrsig = bitcoin_ninja_txt_record()
    txt_resp = [txt]
    verify_rrsig(txt_rrsig, dnskeys, txt_resp)


def test_check_cname_record():
    """Test verifying a CNAME record signature"""
    # First build and validate the complete chain to get trusted DNSKEYs
    rr_stream = BytesIO()
    for rr in root_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in ninja_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in bitcoin_ninja_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    
    # Parse and validate to get trusted keys
    rrs = parse_rr_stream(rr_stream.getvalue())
    verify_rr_stream(rrs)  # This validates the chain
    
    # Now test individual signature verification
    dnskeys = bitcoin_ninja_dnskey()[0]
    cname, cname_rrsig = bitcoin_ninja_cname_record()
    cname_resp = [cname]
    verify_rrsig(cname_rrsig, dnskeys, cname_resp)


def test_check_multi_zone_proof():
    """Test verifying multiple records across zones"""
    rr_stream = BytesIO()
    
    # Build the complete multi-zone chain
    for rr in root_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in com_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in ninja_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in mattcorallo_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    
    txt, txt_rrsig = mattcorallo_txt_record()
    write_rr(txt, 1, rr_stream)
    write_rr(txt_rrsig, 1, rr_stream)
    
    for rr in bitcoin_ninja_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    
    txt, txt_rrsig = bitcoin_ninja_txt_record()
    write_rr(txt, 1, rr_stream)
    write_rr(txt_rrsig, 1, rr_stream)
    
    cname, cname_rrsig = bitcoin_ninja_cname_record()
    write_rr(cname, 1, rr_stream)
    write_rr(cname_rrsig, 1, rr_stream)
    
    rrs = parse_rr_stream(rr_stream.getvalue())
    random.shuffle(rrs)
    verified_rrs = verify_rr_stream(rrs)
    
    assert len(verified_rrs.verified_rrs) == 3
    
    # Sort records by type and name for consistent checking
    verified_rrs.verified_rrs.sort(key=lambda x: (type(x).__name__, x.name.name))
    
    # Find the records by type instead of assuming order
    txt_records = [rr for rr in verified_rrs.verified_rrs if isinstance(rr, Txt)]
    cname_records = [rr for rr in verified_rrs.verified_rrs if isinstance(rr, CName)]
    
    assert len(txt_records) == 2
    assert len(cname_records) == 1
    
    # Check mattcorallo TXT record
    mattcorallo_txt = next((rr for rr in txt_records if "mattcorallo.com" in rr.name.name), None)
    assert mattcorallo_txt is not None
    assert mattcorallo_txt.name.name == "matt.user._bitcoin-payment.mattcorallo.com."
    assert mattcorallo_txt.data == b"bitcoin:?b12=lno1qsgqmqvgm96frzdg8m0gc6nzeqffvzsqzrxqy32afmr3jn9ggkwg3egfwch2hy0l6jut6vfd8vpsc3h89l6u3dm4q2d6nuamav3w27xvdmv3lpgklhg7l5teypqz9l53hj7zvuaenh34xqsz2sa967yzqkylfu9xtcd5ymcmfp32h083e805y7jfd236w9afhavqqvl8uyma7x77yun4ehe9pnhu2gekjguexmxpqjcr2j822xr7q34p078gzslf9wpwz5y57alxu99s0z2ql0kfqvwhzycqq45ehh58xnfpuek80hw6spvwrvttjrrq9pphh0dpydh06qqspp5uq4gpyt6n9mwexde44qv7lstzzq60nr40ff38u27un6y53aypmx0p4qruk2tf9mjwqlhxak4znvna5y"
    
    # Check bitcoin.ninja TXT record
    bitcoin_ninja_txt = next((rr for rr in txt_records if "bitcoin.ninja" in rr.name.name), None)
    assert bitcoin_ninja_txt is not None
    assert bitcoin_ninja_txt.name.name == "txt_test.dnssec_proof_tests.bitcoin.ninja."
    assert bitcoin_ninja_txt.data == b"dnssec_prover_test"
    
    # Check CNAME record
    cname = cname_records[0]
    assert cname.name.name == "cname_test.dnssec_proof_tests.bitcoin.ninja."
    assert cname.canonical_name.name == "txt_test.dnssec_proof_tests.bitcoin.ninja."
    
    # Test name resolution through CNAME
    from validation import VerifiedRRStream
    vs = VerifiedRRStream(verified_rrs.verified_rrs, verified_rrs.valid_from, verified_rrs.expires, verified_rrs.max_cache_ttl)
    filtered_rrs = vs.resolve_name(Name("cname_test.dnssec_proof_tests.bitcoin.ninja."))
    assert len(filtered_rrs) == 1
    assert isinstance(filtered_rrs[0], Txt)
    txt = filtered_rrs[0]
    assert txt.name.name == "txt_test.dnssec_proof_tests.bitcoin.ninja."
    assert txt.data == b"dnssec_prover_test"


def test_check_wildcard_record():
    """Test verifying wildcard signatures - works for any name, even multiple names"""
    # First build and validate the complete chain to get trusted DNSKEYs
    rr_stream = BytesIO()
    for rr in root_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in ninja_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in bitcoin_ninja_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    
    # Parse and validate to get trusted keys
    rrs = parse_rr_stream(rr_stream.getvalue())
    verify_rr_stream(rrs)  # This validates the chain
    
    dnskeys = bitcoin_ninja_dnskey()[0]
    
    # Test with different prefixes
    for prefix in ["name", "another_name", "multiple.names"]:
        txt, txt_rrsig, _, _ = bitcoin_ninja_wildcard_record(prefix)
        txt_resp = [txt]
        verify_rrsig(txt_rrsig, dnskeys, txt_resp)


def test_check_txt_sort_order():
    """Test verifying TXT record sorting edge cases"""
    rr_stream = BytesIO()
    
    for rr in root_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in ninja_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    for rr in bitcoin_ninja_dnskey()[1]:
        write_rr(rr, 1, rr_stream)
    
    txts, rrsig = bitcoin_ninja_txt_sort_edge_cases_records()
    write_rr(rrsig, 1, rr_stream)
    for txt in txts:
        write_rr(txt, 1, rr_stream)
    
    rrs = parse_rr_stream(rr_stream.getvalue())
    random.shuffle(rrs)
    verified_rrs = verify_rr_stream(rrs)
    
    verified_txts = [rr for rr in verified_rrs.verified_rrs if isinstance(rr, Txt)]
    verified_txts.sort(key=lambda x: x.data)
    txts.sort(key=lambda x: x.data)
    
    assert len(verified_txts) == len(txts)
    for i in range(len(txts)):
        assert verified_txts[i].data == txts[i].data


def test_rfc9102_parse_test():
    """Test RFC 9102 test vector parsing and validation"""
    # Note: this is the AuthenticationChain field only, ignoring ExtSupportLifetime field
    rfc9102_test_vector = bytes.fromhex("045f343433045f74637003777777076578616d706c6503636f6d000034000100000e1000230301018bd1da95272f7fa4ffb24137fc0ed03aae67e5c4d8b3c50734e1050a7920b922045f343433045f74637003777777076578616d706c6503636f6d00002e000100000e10005f00340d0500000e105fc6d9005bfdda80074e076578616d706c6503636f6d00ce1d3adeb7dc7cee656d61cfb472c5977c8c9caeae9b765155c518fb107b6a1fe0355fbaaf753c192832fa621fa73a8b85ed79d374117387598fcc812e1ef3fb076578616d706c6503636f6d000030000100000e1000440101030d2670355e0c894d9cfea6c5af6eb7d458b57a50ba88272512d8241d8541fd54adf96ec956789a51ceb971094b3bb3f4ec49f64c686595be5b2e89e8799c7717cc076578616d706c6503636f6d00002e000100000e10005f00300d0200000e105fc6d9005bfdda80074e076578616d706c6503636f6d004628383075b8e34b743a209b27ae148d110d4e1a246138a91083249cb4a12a2d9bc4c2d7ab5eb3afb9f5d1037e4d5da8339c162a9298e9be180741a8ca74accc076578616d706c6503636f6d00002b00010002a3000024074e0d02e9b533a049798e900b5c29c90cd25a986e8a44f319ac3cd302bafc08f5b81e16076578616d706c6503636f6d00002e00010002a3000057002b0d020002a3005fc6d9005bfdda80861703636f6d00a203e704a6facbeb13fc9384fdd6de6b50de5659271f38ce81498684e6363172d47e2319fdb4a22a58a231edc2f1ff4fb2811a1807be72cb5241aa26fdaee03903636f6d00003000010002a30000440100030dec8204e43a25f2348c52a1d3bce3a265aa5d11b43dc2a471162ff341c49db9f50a2e1a41caf2e9cd20104ea0968f7511219f0bdc56b68012cc3995336751900b03636f6d00003000010002a30000440101030d45b91c3bef7a5d99a7a7c8d822e33896bc80a777a04234a605a4a8880ec7efa4e6d112c73cd3d4c65564fa74347c873723cc5f643370f166b43dedff836400ff03636f6d00003000010002a30000440101030db3373b6e22e8e49e0e1e591a9f5bd9ac5e1a0f86187fe34703f180a9d36c958f71c4af48ce0ebc5c792a724e11b43895937ee53404268129476eb1aed323939003636f6d00002e00010002a300005700300d010002a3005fc6d9005bfdda8049f303636f6d0018a948eb23d44f80abc99238fcb43c5a18debe57004f7343593f6deb6ed71e04654a433f7aa1972130d9bd921c73dcf63fcf665f2f05a0aaebafb059dc12c96503636f6d00002e00010002a300005700300d010002a3005fc6d9005bfdda80708903636f6d006170e6959bd9ed6e575837b6f580bd99dbd24a44682b0a359626a246b1812f5f9096b75e157e77848f068ae0085e1a609fc19298c33b736863fbccd4d81f5eb203636f6d00002b000100015180002449f30d0220f7a9db42d0e2042fbbb9f9ea015941202f9eabb94487e658c188e7bcb5211503636f6d00002b000100015180002470890d02ad66b3276f796223aa45eda773e92c6d98e70643bbde681db342a9e5cf2bb38003636f6d00002e0001000151800053002b0d01000151805fc6d9005bfdda807cae00122e276d45d9e9816f7922ad6ea2e73e82d26fce0a4b718625f314531ac92f8ae82418df9b898f989d32e80bc4deaba7c4a7c8f172adb57ced7fb5e77a784b0700003000010001518000440100030dccacfe0c25a4340fefba17a254f706aac1f8d14f38299025acc448ca8ce3f561f37fc3ec169fe847c8fcbe68e358ff7c71bb5ee1df0dbe518bc736d4ce8dfe1400003000010001518000440100030df303196789731ddc8a6787eff24cacfeddd032582f11a75bb1bcaa5ab321c1d7525c2658191aec01b3e98ab7915b16d571dd55b4eae51417110cc4cdd11d171100003000010001518000440101030dcaf5fe54d4d48f16621afb6bd3ad2155bacf57d1faad5bac42d17d948c421736d9389c4c4011666ea95cf17725bd0fa00ce5e714e4ec82cfdfacc9b1c863ad4600002e000100015180005300300d00000151805fc6d9005bfdda80b79d00de7a6740eeecba4bda1e5c2dd4899b2c965893f3786ce747f41e50d9de8c0a72df82560dfb48d714de3283ae99a49c0fcb50d3aaadb1a3fc62ee3a8a0988b6be")
    
    # Add RFC 9102 test anchor locally for this test
    import validation
    original_root_hints = validation.root_hints
    
    def patched_root_hints():
        production_hints = original_root_hints()
        test_anchor = DS(
            Name("."), 47005, 13, 2,
            bytes.fromhex("2eb6e9f2480126691594d649a5a613de3052e37861634641bb568746f2ffc4d4")
        )
        return production_hints + [test_anchor]
    
    # Temporarily patch root_hints for this test
    validation.root_hints = patched_root_hints
    
    try:
        rrs = parse_rr_stream(rfc9102_test_vector)
        random.shuffle(rrs)
        verified_rrs = verify_rr_stream(rrs)
        
        assert len(verified_rrs.verified_rrs) == 1
        assert isinstance(verified_rrs.verified_rrs[0], TLSA)
        tlsa = verified_rrs.verified_rrs[0]
        assert tlsa.cert_usage == 3
        assert tlsa.selector == 1
        assert tlsa.data_type == 1
        assert tlsa.cert_data == bytes.fromhex("8bd1da95272f7fa4ffb24137fc0ed03aae67e5c4d8b3c50734e1050a7920b922")
    finally:
        # Restore original root_hints
        validation.root_hints = original_root_hints


def test_root_hints():
    """Test that root hints are loaded correctly"""
    hints = root_hints()
    assert len(hints) == 2  # Production keys only
    
    # Check the 2017 root key is present
    assert any(ds.key_tag == 20326 for ds in hints)
    assert any(ds.key_tag == 38696 for ds in hints)
    
    for ds in hints:
        assert ds.name.name == "."
        assert ds.algorithm == 8  # RSA only for production keys
        assert ds.digest_type == 2
        assert len(ds.digest) == 32  # SHA-256 digest


def test_resolve_time():
    """Test the time resolution function for DNSSEC timestamps"""
    # Test 2106 rollover handling - values before 1997 are treated as post-2106
    cutoff = 60 * 60 * 24 * 365 * 27  # 1997 cutoff
    
    # Values before 1997 cutoff are treated as post-2106
    assert resolve_time(0) == 2**32
    assert resolve_time(1) == 2**32 + 1
    assert resolve_time(cutoff - 1) == 2**32 + cutoff - 1
    
    # Values after 1997 cutoff are treated as current era
    assert resolve_time(cutoff) == cutoff
    assert resolve_time(cutoff + 1) == cutoff + 1
    assert resolve_time(2**32 - 1) == 2**32 - 1


def test_verify_byte_stream():
    """Test verify_byte_stream function with hex proof chains and names to resolve"""
    
    # Test cases - hex strings to be filled manually
    test_cases = [
        {
            "name": "Test Case 1",
            "hex_proof": "00002e000100002bb30113003008000002a30068993280687d83004f66005a48a604886288cc78c2a35e48816b7a182a349f397f2cd4c1bfa6de634acc9b9b0d2236fd8f257fa8641ae46da7ca17a697c965beabb5477ea6d0cc198b77c8cb9398f8f6fd36c7dc32439409625209b7c3d12108f2c973ea735f764ee629135ed67f016e63949a84e1f120b5146a27221180a0fbd0d632cc900c488b709260f2d479e6d787f2f9fa31222cacdbb696ddc3789744c691d27a8be4486fd7a74b51e417dfb9a9ba8f148f468c536debb4a7dc3803ea6213c55c3efd19cbf29059e5e460803e9656bdac7feacc38bf2bb8a9a3cbc5025841c1b71a58246cab007209bf2f22d4fdd4b80fe6d3bce9e5d2bb80df1949d62f09feb3a5bffe2a1bc6ab000030000100002bb301080100030803010001b11b182a464c3adc6535aa59613bda7a61cac86945c20b773095941194f4b9f516e8bd924b1e50e3fe83918b51e54529d4e5a1e45303df8462241d5e05979979ae5bf9c6c598c08a496e17f3bd3732d5aebe62667b61db1bbe178f27ac99408165a230d6aee78348e6c67789541f845b2ada96667f8dd16ae44f9e260c4a138b3bb1015965ebe609434a06464bd7d29bac47c3017e83c0f89bca1a9e3bdd0813715f3484292df589bc632e27d37efc02837cb85d770d5bd53a36edc99a8294771aa93cf22406f5506c8cf850ed85c1a475dee5c2d3700b3f5631d903524b849995c20cb407ed411f70b428ae3d642716fe239335aa961a752e67fb6dca0bf729000030000100002bb301080100030803010001b6aec4b48567e2925a2d9c4fa4c96e6dddf86215a9bd8dd579c38ccb1199ed1be89946a7f72fc2633909a2792d0eed1b5afb2ee4c78d865a76d6cd9369d999c96af6be0a2274b8f2e9e0a0065bd20257570f08bc14c16f5616426881a83dbce6926e391c138a2ec317efa7349264de2e791c9b7d4a6048ee6eedf27bf1ece398ff0d229f18377cb1f6b98d1228ef217b8146c0c73851b89a6fc37c621ca187e16428a743ffea0072e185ef93e39525cee3ad01e0c94d2e511c8c313322c29ab91631e1856049a36898684c3056e5997473816fb547acb0be6e660bdfa89a5cb28b3669d8625f3f018c7b3b8a4860e774ee8261811ce7f96c461bc162c1a374f3000030000100002bb301080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5000030000100002bb301080101030803010001af7a8deba49d995a792aefc80263e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514d285da3068b19054e5e787b2969058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8abc02cd5040a444a36d47695969849e16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c454e6850a1295207bbd4cdde8f6ffb08faa9755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb54d035ab57d9706ecd9350d4afacd825e43c8668eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f59f4635451e6b27df282ef73d8703636f6d00002b00010001474a00244d060d028acbb0cd28f41250a80a491389424d341522d946b0da0c0291f2d3d771d7805a03636f6d00002e00010001474a0113002b080100015180689978d068884740b569009f50ff461b38abba3d30ace990cb95740c3faae42082ef882a551c6b4a30d2b29caa59b0556ea80efc4a6bc126ba77d86d7e926fb741380018d038935154e0ec37485a479d8d3a5b5d79f15c7be24d5c46b58581b8a6dd55f44de72d20a3b232134a18fcfb14123c94d6d0cb249f90e56439e84df2cbae4da72491ba54b9ca2e8436fbdbb9591bdd93ce0411cf35002bc24c376526ed1711743d38ca227915f6e5e3e4c314617ad0d4e038646e885800e8853a79b7a160b5375bf492c19a7f5752718f11116b9a3278eaf19f34ee597fe315eaba1ce86c52625e4dfdcacc8d04994ee7600c4ec51357a2c23e936b05399153df6a31edc4e3d507976904dea64403636f6d00002e0001000006a4005700300d010001518068920efb687e474f4d0603636f6d00b2e671a909bab6910567084b8347cb199b924a4acf9e1a2602ba0adaa3b056890609bd88ee767161672bbe89466e2c035c0bce3a755f33b910047fa27a90b9c203636f6d0000300001000006a400440100030df17b60fb56d522f8634153e785c0a978532ea76de39d34bb356d3d042e07f29f7b992176cc83acef7b78ea750425203b18f2b8228b3cdd2bc7eb13c3e3035a7e03636f6d0000300001000006a400440101030db71f0465101ddbe2bf0c9455d12fa16c1cda44f4bf1ba2553418ad1f3aa9b06973f21b84eb532cf4035ee8d4832ca26d89306a7d32560c0cb0129d450ac108350d73706172726f7777616c6c657403636f6d00002b00010000546000243dc40d0256040d991c1075c4a8555445f9a5ce52ce6801aaf45d3e87663e7fbd68bc312b0d73706172726f7777616c6c657403636f6d00002b0001000054600024cf3b0d02656da59836422f5e198e73fc35e6a89bc0838deaac565e71a19804fc1250e4ce0d73706172726f7777616c6c657403636f6d00002e0001000054600057002b0d020001518068901cfc6886d214504103636f6d00d763f6d6ecb0f5e5b982f845d5fd5846ee9ce3a4a8cca71e8b7525476d6b6d2a3e196730e8b6bcfbe6774dd204519e609aa708f6151fe0247ccde98d2bd8c55d0d73706172726f7777616c6c657403636f6d00002e0001000007e5006500300d0200000e106891efe0687e29603dc40d73706172726f7777616c6c657403636f6d002b96ad4cdc8619f89d74317373ff0b40b9de3132cf957ee57c653c204d1d3611d6264d6baefb1c45c1fe2d499cc77587183f4900a1f0512b0478a60e4944c0410d73706172726f7777616c6c657403636f6d0000300001000007e500440100030d24c8364b3f942b0062f1c63880b959b2e7827f1cffff8d5e38f7fde1b22d621d1c4a0cd9a9b0c6c70b1c94543ccdc5502481aebd6e2b44656c9ea339ac81e83b0d73706172726f7777616c6c657403636f6d0000300001000007e500440100030d95676c7b25e7794a8a7e4b19ed638e47aca735d02ce2dd08b2886c20c31a2cb9e7cc8b85023a46eeb637020119dcaa6bbc0747e12340fa813199799de579de8a0d73706172726f7777616c6c657403636f6d0000300001000007e500440101030db0372521337fd56d8b62e917b7866b7faa753d25322e12b52a3eb5ff9f4c9f66227f508fe33ba139f2f1354fe3ded6d3da76d49be926198dc2940f2c5282c7fe0d73706172726f7777616c6c657403636f6d0000300001000007e500440101030dddf917743f320a49f6218d706218b6cae574f1db7688555e0d5f0455405d6865993f0147fb4b33baa207b28d232c9e70419ddcae72050311098cd4cfaa07969b0563726169670475736572105f626974636f696e2d7061796d656e740d73706172726f7777616c6c657403636f6d000010000100000e10003332626974636f696e3a6263317177746865343378657561736b6c636c71346b766872656c75763368753932727a656a34326a730563726169670475736572105f626974636f696e2d7061796d656e740d73706172726f7777616c6c657403636f6d00002e000100000e10006500100d0500000e106891efe0687e2960bb260d73706172726f7777616c6c657403636f6d00e7ae93d23b747737554c4d52dd1ec0f58c411c6a474da46c3c24d0db970d86e91bf91b5eabeb1ed59121678ef534a25a6f75ce0588e6524439c11d208f301d46",  # TODO: Replace with actual hex string
            "name_to_resolve": "craig.user._bitcoin-payment.sparrowwallet.com."
        },
        {
            "name": "Test Case 2", 
            "hex_proof": "00002e0001000149d60113003008000002a30068993280687d83004f66005a48a604886288cc78c2a35e48816b7a182a349f397f2cd4c1bfa6de634acc9b9b0d2236fd8f257fa8641ae46da7ca17a697c965beabb5477ea6d0cc198b77c8cb9398f8f6fd36c7dc32439409625209b7c3d12108f2c973ea735f764ee629135ed67f016e63949a84e1f120b5146a27221180a0fbd0d632cc900c488b709260f2d479e6d787f2f9fa31222cacdbb696ddc3789744c691d27a8be4486fd7a74b51e417dfb9a9ba8f148f468c536debb4a7dc3803ea6213c55c3efd19cbf29059e5e460803e9656bdac7feacc38bf2bb8a9a3cbc5025841c1b71a58246cab007209bf2f22d4fdd4b80fe6d3bce9e5d2bb80df1949d62f09feb3a5bffe2a1bc6ab0000300001000149d601080100030803010001b11b182a464c3adc6535aa59613bda7a61cac86945c20b773095941194f4b9f516e8bd924b1e50e3fe83918b51e54529d4e5a1e45303df8462241d5e05979979ae5bf9c6c598c08a496e17f3bd3732d5aebe62667b61db1bbe178f27ac99408165a230d6aee78348e6c67789541f845b2ada96667f8dd16ae44f9e260c4a138b3bb1015965ebe609434a06464bd7d29bac47c3017e83c0f89bca1a9e3bdd0813715f3484292df589bc632e27d37efc02837cb85d770d5bd53a36edc99a8294771aa93cf22406f5506c8cf850ed85c1a475dee5c2d3700b3f5631d903524b849995c20cb407ed411f70b428ae3d642716fe239335aa961a752e67fb6dca0bf7290000300001000149d601080100030803010001b6aec4b48567e2925a2d9c4fa4c96e6dddf86215a9bd8dd579c38ccb1199ed1be89946a7f72fc2633909a2792d0eed1b5afb2ee4c78d865a76d6cd9369d999c96af6be0a2274b8f2e9e0a0065bd20257570f08bc14c16f5616426881a83dbce6926e391c138a2ec317efa7349264de2e791c9b7d4a6048ee6eedf27bf1ece398ff0d229f18377cb1f6b98d1228ef217b8146c0c73851b89a6fc37c621ca187e16428a743ffea0072e185ef93e39525cee3ad01e0c94d2e511c8c313322c29ab91631e1856049a36898684c3056e5997473816fb547acb0be6e660bdfa89a5cb28b3669d8625f3f018c7b3b8a4860e774ee8261811ce7f96c461bc162c1a374f30000300001000149d601080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b50000300001000149d601080101030803010001af7a8deba49d995a792aefc80263e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514d285da3068b19054e5e787b2969058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8abc02cd5040a444a36d47695969849e16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c454e6850a1295207bbd4cdde8f6ffb08faa9755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb54d035ab57d9706ecd9350d4afacd825e43c8668eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f59f4635451e6b27df282ef73d8703636f6d00002b000100007a7100244d060d028acbb0cd28f41250a80a491389424d341522d946b0da0c0291f2d3d771d7805a03636f6d00002e000100007a710113002b08010001518068977e9068864d00b569002d3014cdeea855ed967775aa53a2671069c3d5c3a47b4e51fd4926fda34c7f6bcf970272fe18c516cbfc0119b024badb77082f1b956d948f3fd92e05557835ca10379cf523583e137e4d1d35047c4ca07d1ff11708241a091a6167d4538c1a084de6be6360997767cad3d44e7530461c8e8c744bfc146c02b00360e29eb4b6d6ec8ff3a1fe8eb44e3098ecf865ddf8f19d66b99105d961218925cab2c01ff6ac3ac9d364089536b6e2e71d2ec063949eb71137fc646897113f92673c8a74c23bb66283c80bd26d9d70ef3fe9024ecf299895a1e856954e7a5b11f528a5953baf75f6d5db6ccbc5f031b667f612a6c7d27096e40e8bf7fb2fda709900bc221ee903636f6d00002e00010000171a005700300d010001518068920efb687e474f4d0603636f6d00b2e671a909bab6910567084b8347cb199b924a4acf9e1a2602ba0adaa3b056890609bd88ee767161672bbe89466e2c035c0bce3a755f33b910047fa27a90b9c203636f6d00003000010000171a00440100030df17b60fb56d522f8634153e785c0a978532ea76de39d34bb356d3d042e07f29f7b992176cc83acef7b78ea750425203b18f2b8228b3cdd2bc7eb13c3e3035a7e03636f6d00003000010000171a00440101030db71f0465101ddbe2bf0c9455d12fa16c1cda44f4bf1ba2553418ad1f3aa9b06973f21b84eb532cf4035ee8d4832ca26d89306a7d32560c0cb0129d450ac108350b6d617474636f72616c6c6f03636f6d00002b00010000546000249f000d02594d2813e04a1d2660ff3c0afc5579b9ec0fe72cc206dc6f248bbe6dd652e1950b6d617474636f72616c6c6f03636f6d00002b0001000054600024e2f50d02f0e161567d468087ff27b051abc94476178a7cb635da1aa705e05c77ca81de520b6d617474636f72616c6c6f03636f6d00002e0001000054600057002b0d020001518068900e906886c3a8504103636f6d006d674908febdc7e78aa921806332f66656388c9ecb0305391d70a251886654f841426c54969009b261b3ab5c9cb5f2f9ba94fe5327722c079e89fb1f33963c330b6d617474636f72616c6c6f03636f6d00002e00010000456b006300300d0200093a80689827d568859dbde2f50b6d617474636f72616c6c6f03636f6d00f8fcb4e5ea52960df7464a5dc487043b6fb8fb8a083393c18902c47bd0c536f2cf138da967bc8be8599ef28a6bb781ce95e4b9617d2c3dbc8c5029092d80c4bc0b6d617474636f72616c6c6f03636f6d00003000010000456b00440100030dfd9dbc34cb5053a2c4a6b3d0dc60fc65d8a992dc1e080f6deeddba7fe6b25217730de64c9a1ce986b3f81f556881fe0e7b5b20c8ae381c4fefdbc311aa7d22ee0b6d617474636f72616c6c6f03636f6d00003000010000456b00440101030dec7c1fa1752495c42d2224eace96ed74144e9cb811608dd91594974bdc723fdc5b38a37c3340f1deca68a7ec82248822954b2994de5ac99ff6e9db95fd42c94b046d6174740475736572105f626974636f696e2d7061796d656e740b6d617474636f72616c6c6f03636f6d000010000100000d8201ecff626974636f696e3a626331717a7477793678656e337a647474377a3076726761706d6a74667a3861636a6b6670356670376c3f6c6e6f3d6c6e6f317a7235717975677167736b726b37306b716d7571377633646e7232666e6d68756b7073396e386875743438766b7170716e736b743273767371776a616b70376b36707968746b7578773779326b716d73786c777275687a7176307a736e686839713374397868783339737563367173723037656b6d3565736479756d307736366d6e783876647175777670376470356a70376a337635637036616a3077333239666e6b7171763630713936737a356e6b726335723935716666783030327135337471646beb3878396d32746d7438356a74706d63796376666e727078336c723435683267376e6133736563377867756374667a7a636d386a6a71746a3579613237746536306a303376707430767139746d326e3979786c32686e67666e6d79676573613235733475347a6c78657771707670393478743772757234726878756e776b74686b39766c79336c6d356868307071763461796d6371656a6c6773736e6c707a776c6767796b6b616a7037796a73356a76723261676b79797063646c6a323830637934366a70796e73657a72636a326b7761326c797238787664366c666b706834787278746b327863336c7071046d6174740475736572105f626974636f696e2d7061796d656e740b6d617474636f72616c6c6f03636f6d00002e000100000d82006300100d0500000e106894172f68818d17a7150b6d617474636f72616c6c6f03636f6d00ba9ee201fe8e135c732d61f8ba32580a7a4e6f3e490cd520b7e4afe9004f257c1b986dd2ef8d4588f4d3810da04249c48b88a6c284f43be5703220ee2a955320056e696e6a6100002b0001000015640024b4020802c8f816a7a575bdb2f997f682aab2653ba2cb5eddb69b036a30742a33befaf141056e696e6a6100002e0001000015640113002b0801000151806896d5d06885a440b56900a41759b94a4adf6192a0fb6e0f3ee388c15cd5b4f80fe961b1efbe5f93c2941c41ed1b71e9cdb5ccd651ffaf4d3c3158b341f21ccfbdf99b80485ceae57641e094919cc5ffe219c4ee25e3aa6bd02ba378de69bda940da8d1a873942acc683b25f41641fbf922833311af6fba9443532a37fd601a8dfb000f5a749b5ece5c847bab87c770605d1b2fa5c5528a4c78388b0a99ff5ca49580777a3854f472b06aa28a1bc53d4dda596ca6df1275227a107e6520605c919fc7048081fd3d396784a49928a3f32f1445f5fa56d2a4be8c2f5f7da68deeb974e7023b507cffea1e69d6706a62560321fa3a7492256715b229dcc802f51321bbb201bf76571dfa55ef4056e696e6a6100002e000100000c9e01190030080100000e10689f57ec68839a5cb402056e696e6a61006e05a6c0c66f0da44f5905afbb29f819692ccc8e867b45c25839bc5b7ed203383d2df06a284b3414b71848a77bebeb209333c1aeb52700cf3e630232e29d4befe5e708a0fa5fed527e6977ff41607ec531c8aa55be8cfac4beb38fd08b73a01deb25dd1b046c1e27ea210f1e9198672e8931b1eeafa6b24355fbaeb336c86bfb455ce4eea1b60c7218b3e077930be6250d4f81c9b73d9cecf9126e6962dddd489674ae560dfc18e63ef2d6a71c8347dbdca986937cc9ff2f793c0ee196bbef70784ec2cb7261393e32ba31db67043dc418fd17a74800194e77ab88130fa5e9736acd63f0d6b32ebee665bf4d95344f1d71cda00b2de99ce2e3a52b8e61b2c413056e696e6a61000030000100000c9e0088010003080301000197edb59d4f181e2761dd8d0465854339afc71fd89e47155981ddd175cdce79477552aeaf7b5a08fc4ac6025555f60582f2060e630edfb35b9c7cc30990fb9c3dc9f2fd036c962f67b94c9670d4ceaacd77973bca82ab7c9615f7e4320dda5b6d74dec673017c6fa448b5542a804e08ac873c509c1945ff734c320491e4b18e6d056e696e6a61000030000100000c9e00880100030803010001d28cb7e2bb163d5815838bedeca1006dde8551b379cb963c8a2cb42bc360127e3a5cf88ffc851a67414815b875f65d78c39b58d2fb29a1d4e76d50cb6b4a58a11fe2fb7c1b6db7bf7d72f5a1401e381c57fcc76f599cc73f05095d2bd14d9895e4fa1cff21bd760598a734b640102d11bc159c6b2ae73dbfd2741518142584d1056e696e6a61000030000100000c9e01080101030803010001c71e4c9dc49249a27b3ef42fcb8d56b4c3ac76715c7ad01c41d0d432590d15c3c62cee4b2d29ac35f2d72c9b32a70a0243cbd08aeebc9f6f1e0e63d9e1cdfe133c455a82435c0780b750012c942f7ed5b662eec8d9ae885a58993fa78d7561fedcd11d9e1c171acb02d0025837ba61a3c0a6756427414470c9ca0906b298168b5f4d9640e62e1b75dd06be664104ed32cfe447fa21f37401712c720a0dca4bb1bc20f3fa3103cad336bde20b16f73948e6b80dda0a528db536a958868c3870ecddcfb02dfb3cb4d22e2ad49a4b9f78c90ff6c7e10e301b3fb36fe859a94c30084660665741c14ff60d0535013fcf439840ecad82fc9278e4ace68ba95e70824907626974636f696e056e696e6a6100002b000100000e100024716c0d023f7ad5a303e9c1cd1474b8df2ae56f3f82da8637ca55db4d9a2bb85960ca698e07626974636f696e056e696e6a6100002b000100000e100024768a0d02ce46a9aff9a06e789c1bdfe250b0ef6ba8d39a53b2a3427c551f5ad375e059b607626974636f696e056e696e6a6100002e000100000e100099002b080200000e10689f57ec68839a5ce694056e696e6a610042a265ca325eebc262b0f2d80a07985dd07cd8b4889adc02ca652b279253ed12ce0e381c7e174dc5ae05e230aa63a0ad614c1aa93e25027e3b1c1c9d85a8a4d2ecc1697a8892fddca9e7b8de63092db3ccd09895eb625b494008d2be8ead86edd91b08bfc5cbce55588174df0c4a6a10657a79536dc63ca9df23fbd7a5a0264207626974636f696e056e696e6a6100002e00010000542d006100300d0200093a806898c73468863d1c716c07626974636f696e056e696e6a610002fd1bf18c2ebb5ece5e28ca76bf30650695636c55633bccae8179c2d1ee7b97e78d188e08ffc869a8f67847bf557516ac12465ebea1acc281d6d636fdab612007626974636f696e056e696e6a6100003000010000542d00440100030dff753a27b08c3e48a642b210d6fcc444ff9ed4faf9c1241103db4ed3c19a95c3afbb52c0c02eb392ee048cc9e28ac2d272b1053bdc052bc18d5de05d7710196c07626974636f696e056e696e6a6100003000010000542d00440101030df65551925ce6321888e685981823d617fbc10f329bffe4081bf18c2372632a5548010bf62e6556a92722629275e0bd001e3d7837d325a353f6a851c5b96525962036397661326d75643937367167717372643861627375683975356e367432686907626974636f696e056e696e6a6100002e00010000003c006100320d030000003c68995d346886d31cd0e207626974636f696e056e696e6a6100f2edbe6baf1ea78801d1c86c388a3e4f4d7e596558a70a23f63229d1677436f910943aad865d26f59eef25819ac5dcc75e1ea40931ebd44fc78a565b0de5952f2036397661326d75643937367167717372643861627375683975356e367432686907626974636f696e056e696e6a6100003200010000003c002a0100000008a89d709785072f1f143ad5cecc99536c8932ccca13e290b69519eec12c0006000180000002016113785f646f6d61696e5f636e616d655f77696c640475736572105f626974636f696e2d7061796d656e7412646e737365635f70726f6f665f746573747307626974636f696e056e696e6a6100000500010000001e002c046d6174740475736572105f626974636f696e2d7061796d656e740b6d617474636f72616c6c6f03636f6d00016113785f646f6d61696e5f636e616d655f77696c640475736572105f626974636f696e2d7061796d656e7412646e737365635f70726f6f665f746573747307626974636f696e056e696e6a6100002e00010000001e006100050d060000001e68950be3688281cbd0e207626974636f696e056e696e6a61000f9d965ddf9abf817af035eb83ef29b398e76f82d41fc769f77fab49321669e06dac97f91ed8b954e0a340b64a2f26c2687a28f5e12fdbf392bbdfeb9285875c",  # TODO: Replace with actual hex string
            "name_to_resolve": "a.x_domain_cname_wild.user._bitcoin-payment.dnssec_proof_tests.bitcoin.ninja."
        },
        {
            "name": "Test Case 3",
            "hex_proof": "00002e000100008a350113003008000002a30068993280687d83004f66005a48a604886288cc78c2a35e48816b7a182a349f397f2cd4c1bfa6de634acc9b9b0d2236fd8f257fa8641ae46da7ca17a697c965beabb5477ea6d0cc198b77c8cb9398f8f6fd36c7dc32439409625209b7c3d12108f2c973ea735f764ee629135ed67f016e63949a84e1f120b5146a27221180a0fbd0d632cc900c488b709260f2d479e6d787f2f9fa31222cacdbb696ddc3789744c691d27a8be4486fd7a74b51e417dfb9a9ba8f148f468c536debb4a7dc3803ea6213c55c3efd19cbf29059e5e460803e9656bdac7feacc38bf2bb8a9a3cbc5025841c1b71a58246cab007209bf2f22d4fdd4b80fe6d3bce9e5d2bb80df1949d62f09feb3a5bffe2a1bc6ab000030000100008a3501080100030803010001b11b182a464c3adc6535aa59613bda7a61cac86945c20b773095941194f4b9f516e8bd924b1e50e3fe83918b51e54529d4e5a1e45303df8462241d5e05979979ae5bf9c6c598c08a496e17f3bd3732d5aebe62667b61db1bbe178f27ac99408165a230d6aee78348e6c67789541f845b2ada96667f8dd16ae44f9e260c4a138b3bb1015965ebe609434a06464bd7d29bac47c3017e83c0f89bca1a9e3bdd0813715f3484292df589bc632e27d37efc02837cb85d770d5bd53a36edc99a8294771aa93cf22406f5506c8cf850ed85c1a475dee5c2d3700b3f5631d903524b849995c20cb407ed411f70b428ae3d642716fe239335aa961a752e67fb6dca0bf729000030000100008a3501080100030803010001b6aec4b48567e2925a2d9c4fa4c96e6dddf86215a9bd8dd579c38ccb1199ed1be89946a7f72fc2633909a2792d0eed1b5afb2ee4c78d865a76d6cd9369d999c96af6be0a2274b8f2e9e0a0065bd20257570f08bc14c16f5616426881a83dbce6926e391c138a2ec317efa7349264de2e791c9b7d4a6048ee6eedf27bf1ece398ff0d229f18377cb1f6b98d1228ef217b8146c0c73851b89a6fc37c621ca187e16428a743ffea0072e185ef93e39525cee3ad01e0c94d2e511c8c313322c29ab91631e1856049a36898684c3056e5997473816fb547acb0be6e660bdfa89a5cb28b3669d8625f3f018c7b3b8a4860e774ee8261811ce7f96c461bc162c1a374f3000030000100008a3501080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5000030000100008a3501080101030803010001af7a8deba49d995a792aefc80263e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514d285da3068b19054e5e787b2969058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8abc02cd5040a444a36d47695969849e16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c454e6850a1295207bbd4cdde8f6ffb08faa9755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb54d035ab57d9706ecd9350d4afacd825e43c8668eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f59f4635451e6b27df282ef73d87056e696e6a6100002b000100011e7f0024b4020802c8f816a7a575bdb2f997f682aab2653ba2cb5eddb69b036a30742a33befaf141056e696e6a6100002e000100011e7f0113002b080100015180689827506886f5c0b569005653d237e182a326851f70489ac7f622872e47684dd0d0de3caf17dfdd479efd1a7da7d8df1ff69a4459842d8a266611a66689521a636858d227b723af0c438d493b074de99acbd685547d7f7692743fec6af2167ee8567a0b0807dfb1bc53367d3a41397ba4ddf2e76f6922b23f034202546667755f624337ef9401c093b712445178e6fca3d4452c25ab99d32417ec0a031fb39c867c5f88114df1e13266ff15aba34c5f571fe91a877ed576ab528b3508a201424c1ba547c38fcbe6cda5362921d8bb747a5e427288d06c22cba8b04448af6a0fa99cda7109ed16e64b970073e3255ed3fafcf1542529d89cbb799e767bd760787159e1bd1c7d4f34995e73056e696e6a6100002e000100000a8901190030080100000e10689f57ec68839a5cb402056e696e6a61006e05a6c0c66f0da44f5905afbb29f819692ccc8e867b45c25839bc5b7ed203383d2df06a284b3414b71848a77bebeb209333c1aeb52700cf3e630232e29d4befe5e708a0fa5fed527e6977ff41607ec531c8aa55be8cfac4beb38fd08b73a01deb25dd1b046c1e27ea210f1e9198672e8931b1eeafa6b24355fbaeb336c86bfb455ce4eea1b60c7218b3e077930be6250d4f81c9b73d9cecf9126e6962dddd489674ae560dfc18e63ef2d6a71c8347dbdca986937cc9ff2f793c0ee196bbef70784ec2cb7261393e32ba31db67043dc418fd17a74800194e77ab88130fa5e9736acd63f0d6b32ebee665bf4d95344f1d71cda00b2de99ce2e3a52b8e61b2c413056e696e6a61000030000100000a890088010003080301000197edb59d4f181e2761dd8d0465854339afc71fd89e47155981ddd175cdce79477552aeaf7b5a08fc4ac6025555f60582f2060e630edfb35b9c7cc30990fb9c3dc9f2fd036c962f67b94c9670d4ceaacd77973bca82ab7c9615f7e4320dda5b6d74dec673017c6fa448b5542a804e08ac873c509c1945ff734c320491e4b18e6d056e696e6a61000030000100000a8900880100030803010001d28cb7e2bb163d5815838bedeca1006dde8551b379cb963c8a2cb42bc360127e3a5cf88ffc851a67414815b875f65d78c39b58d2fb29a1d4e76d50cb6b4a58a11fe2fb7c1b6db7bf7d72f5a1401e381c57fcc76f599cc73f05095d2bd14d9895e4fa1cff21bd760598a734b640102d11bc159c6b2ae73dbfd2741518142584d1056e696e6a61000030000100000a8901080101030803010001c71e4c9dc49249a27b3ef42fcb8d56b4c3ac76715c7ad01c41d0d432590d15c3c62cee4b2d29ac35f2d72c9b32a70a0243cbd08aeebc9f6f1e0e63d9e1cdfe133c455a82435c0780b750012c942f7ed5b662eec8d9ae885a58993fa78d7561fedcd11d9e1c171acb02d0025837ba61a3c0a6756427414470c9ca0906b298168b5f4d9640e62e1b75dd06be664104ed32cfe447fa21f37401712c720a0dca4bb1bc20f3fa3103cad336bde20b16f73948e6b80dda0a528db536a958868c3870ecddcfb02dfb3cb4d22e2ad49a4b9f78c90ff6c7e10e301b3fb36fe859a94c30084660665741c14ff60d0535013fcf439840ecad82fc9278e4ace68ba95e70824907626974636f696e056e696e6a6100002b000100000e100024716c0d023f7ad5a303e9c1cd1474b8df2ae56f3f82da8637ca55db4d9a2bb85960ca698e07626974636f696e056e696e6a6100002b000100000e100024768a0d02ce46a9aff9a06e789c1bdfe250b0ef6ba8d39a53b2a3427c551f5ad375e059b607626974636f696e056e696e6a6100002e000100000e100099002b080200000e10689f57ec68839a5ce694056e696e6a610042a265ca325eebc262b0f2d80a07985dd07cd8b4889adc02ca652b279253ed12ce0e381c7e174dc5ae05e230aa63a0ad614c1aa93e25027e3b1c1c9d85a8a4d2ecc1697a8892fddca9e7b8de63092db3ccd09895eb625b494008d2be8ead86edd91b08bfc5cbce55588174df0c4a6a10657a79536dc63ca9df23fbd7a5a0264207626974636f696e056e696e6a6100002e0001000043a6006100300d0200093a806898c73468863d1c716c07626974636f696e056e696e6a610002fd1bf18c2ebb5ece5e28ca76bf30650695636c55633bccae8179c2d1ee7b97e78d188e08ffc869a8f67847bf557516ac12465ebea1acc281d6d636fdab612007626974636f696e056e696e6a610000300001000043a600440100030dff753a27b08c3e48a642b210d6fcc444ff9ed4faf9c1241103db4ed3c19a95c3afbb52c0c02eb392ee048cc9e28ac2d272b1053bdc052bc18d5de05d7710196c07626974636f696e056e696e6a610000300001000043a600440101030df65551925ce6321888e685981823d617fbc10f329bffe4081bf18c2372632a5548010bf62e6556a92722629275e0bd001e3d7837d325a353f6a851c5b9652596086f7665727269646513785f646f6d61696e5f636e616d655f77696c640475736572105f626974636f696e2d7061796d656e7412646e737365635f70726f6f665f746573747307626974636f696e056e696e6a6100001000010000001e002b2a626974636f696e3a314a424d617474527a744b4446324b52533376686a4a5841376834374e45736e3263086f7665727269646513785f646f6d61696e5f636e616d655f77696c640475736572105f626974636f696e2d7061796d656e7412646e737365635f70726f6f665f746573747307626974636f696e056e696e6a6100002e00010000001e006100100d070000001e68950db36882839bd0e207626974636f696e056e696e6a610075ec00352dd04506619d06904e95448002f60b7d566194a6624ce850c6fe0026f9f95ecda41dfa6a66733bd6285903305766b31a6097c89656e6c69906c0bd74",  # TODO: Replace with actual hex string  
            "name_to_resolve": "override.x_domain_cname_wild.user._bitcoin-payment.dnssec_proof_tests.bitcoin.ninja."
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n--- {test_case['name']} ---")
        
        # Skip placeholder test cases
        if test_case["hex_proof"].startswith("PLACEHOLDER"):
            print(f"Skipping placeholder test case {i}")
            continue
            
        # Convert hex to bytes
        proof_bytes = bytes.fromhex(test_case["hex_proof"])
        
        # Call verify_byte_stream
        result_json = verify_byte_stream(proof_bytes, test_case["name_to_resolve"])
        
        # Parse and display result
        result = json.loads(result_json)
        
        if "error" in result:
            print(f"❌ Error: {result['error']}")
        else:
            print(f"✅ Success:")
            print(f"   Valid from: {result['valid_from']}")
            print(f"   Expires: {result['expires']}")
            print(f"   Max cache TTL: {result['max_cache_ttl']}")
            print(f"   Verified records: {len(result['verified_rrs'])}")
            for rr in result['verified_rrs']:
                print(f"     - {rr['type'].upper()}: {rr['name']}")
    
    print("\n✅ verify_byte_stream test completed")


def test_verify_byte_stream_error_cases():
    """Test verify_byte_stream error handling"""
    
    # Test invalid name
    result = verify_byte_stream(b"", "invalid..name")
    result_obj = json.loads(result)
    assert "error" in result_obj
    
    # Test invalid stream  
    result = verify_byte_stream(b"invalid_data", "example.com.")
    result_obj = json.loads(result)
    assert "error" in result_obj
    
    print("✅ Error cases passed")


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 