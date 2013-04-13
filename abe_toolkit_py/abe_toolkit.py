#! /usr/bin/env python
import os, platform, subprocess
from ctypes import CDLL

# Lib name postfix
postfix = ''

sysstr = platform.system()
if sysstr == 'Windows':
    # Add current dir to system PATH environment
    modulepath = os.path.abspath(__file__)
    moduledir = os.path.dirname(modulepath)
    PATH = os.getenv('PATH', '')
    PATH = ';'.join([moduledir, PATH])
    os.environ['PATH'] = PATH
    # Windows lib has a version number
    postfix = '-0'
elif sysstr == 'Linux':
    # Linux lib has .so postfix
    postfix = '.so'

# FENC toolkit lib file paths
libabe_setup_name = 'libabe-setup' + postfix
libabe_keygen_name = 'libabe-keygen' + postfix
libabe_enc_name = 'libabe-enc' + postfix
libabe_dec_name = 'libabe-dec' + postfix
libpolicy_test_name = 'libpolicy-test' + postfix
# libs for KSF-CP-ABE only
libabe_ukeygen_name = 'libabe-ukeygen' + postfix
libksf_keygen_name = 'libksf-keygen' + postfix
libksf_trapdoor_name = 'libksf-trapdoor' + postfix
libksf_search_name = 'libksf-search' + postfix
libabe_qdec_name = 'libabe-qdec' + postfix

# Predefine file path
# Group parameters file path
group_params = 'param/d224.param'
# Secret parameters file path
secret_params = 'param/SP.txt'
# Public parameters file path
public_params = 'param/PP.txt'

# FENC_SCHEME_TYPE
(
    FENC_SCHEME_NONE,
    FENC_SCHEME_LSW,  # KP-ABE GPSW06
    FENC_SCHEME_WATERSCP,  # CP-ABE Waters08
    FENC_SCHEME_WATERSSIMPLECP,  # CP-ABE Waters08 Simple
    FENC_SCHEME_KSFCP  # CP-ABE base on Waters08 with keyword search function
) = range(5)

def setup(scheme=FENC_SCHEME_KSFCP, group_params=group_params, secret_params=secret_params, public_params=public_params):
    """
    @param scheme: ABE scheme
    @param group_params: Group parameters file path
    @param secret_params: Secret parameters file path
    @param public_params: Public parameters file path
    @return: Setup status: 0 - OK, not 0 - ERROR
    """
    libabe_setup = CDLL(libabe_setup_name)
    result = libabe_setup.gen_abe_scheme_params(scheme, group_params, secret_params, public_params)
    return result
    
def keygen(key_string, scheme=FENC_SCHEME_KSFCP, group_params=group_params, secret_params=secret_params, public_params=public_params,
           key_file='key.txt'):
    """
    @param key_string: Attribute string or Policy string
    @param scheme: ABE scheme
    @param group_params: Group parameters file path
    @param secret_params: Secret parameters file path
    @param public_params: Public parameters file path
    @param key_file: Output decryption key file path
    @return: KeyGen status: 0 - OK, not 0 - ERROR
    """
    libabe_keygen = CDLL(libabe_keygen_name)
    result = libabe_keygen.generate_keys_with_string(scheme, key_string, group_params, secret_params, public_params, key_file)
    return result

def encrypt(key_string, data_file, scheme=FENC_SCHEME_KSFCP, group_params=group_params, public_params=public_params,
            enc_file='encrypted.txt', keyword_file=0, index_file='index.txt'):
    """
    @param key_string: Attribute string or Policy string
    @param data_file: Data file path for encryption
    @param scheme: ABE scheme
    @param group_params: Group parameters file path
    @param secret_params: Secret parameters file path
    @param public_params: Public parameters file path
    @param enc_file: Output encrypted file path (no postfix)
    @param keyword_file: Input keywords file path, to gen index, used in KSF
    @param index_file: Output index file path, used in KSF 
    @return: Encrytion status: 0 - OK, not 0 - ERROR
    """
    
    # param isXML: Output format, 0 - txt, 1 - XML
    isXML = 0
    # param ext: Output Encrypted file path extendion string (postfix)
    ext = enc_file[-3:]
    enc_file = enc_file[:-4]
    if ext.lower() == 'xml':
        isXML = 1
    
    libabe_enc = CDLL(libabe_enc_name)
    result = libabe_enc.abe_encrypt_from_file(scheme, key_string, group_params, public_params, data_file, enc_file, isXML, ext, keyword_file, index_file)
    return result

def decrypt(scheme=FENC_SCHEME_KSFCP, group_params=group_params, public_params=public_params,
            input_file='encrypted.txt', key_file='key.txt', dec_file='decrypted.txt'):
    """
    @param scheme: ABE scheme
    @param group_params: Group parameters file path
    @param public_params: Public parameters file path
    @param input_file: Input encrypted file path
    @param key_file: Input decryption key file path
    @param dec_file: Output decrypted file path (with postfix)
    @return: Decrytion status: 0 - OK, not 0 - ERROR
    """
    libabe_dec = CDLL(libabe_dec_name)
    result = libabe_dec.abe_decrypt(scheme, group_params, public_params, input_file, key_file, dec_file)
    return result

def policy_test(policy_string, debug=False):
    """
    @param policy_string: Policy string for test
    @param debug: Set True to show debug result
    @return: 0 - OK, not 0 - ERROR, result string when debug=True
    """
    if debug:
        args = ['policy-test', policy_string]
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        return stdoutdata, stderrdata
    else:
        libpolicy_test = CDLL(libpolicy_test_name)
        result = libpolicy_test.test_policy_string(policy_string)
        return result

# Functions for keyword search

def ukeygen(group_params=group_params, public_params=public_params,
            usk_file='usk.txt', upk_file='upk.txt'):
    """
    @param group_params: Group parameters file path
    @param public_params: Public parameters file path
    @param usk_file: Output USK file path
    @param upk_file: Output UPK file path
    @return: Encrytion status: 0 - OK, not 0 - ERROR
    """
    scheme = FENC_SCHEME_KSFCP
    libabe_ukeygen = CDLL(libabe_ukeygen_name)
    result = libabe_ukeygen.gen_ukeys(scheme, group_params, public_params, usk_file, upk_file)
    return result

def ksf_keygen(group_params=group_params, public_params=public_params, secret_params=secret_params,
            key_file='key.txt', upk_file='upk.txt', ksf_key_file='ksf_key.txt'):
    """
    @param group_params: Group parameters file path
    @param secret_params: Secret parameters file path
    @param public_params: Public parameters file path
    @param key_file: Input decryption key file path
    @param upk_file: Input UPK file path
    @param ksf_key_file: Output KSF key file path
    @return: Encrytion status: 0 - OK, not 0 - ERROR
    """
    scheme = FENC_SCHEME_KSFCP
    libksf_keygen = CDLL(libksf_keygen_name)
    result = libksf_keygen.generate_ksfkeys(scheme, group_params, public_params, secret_params, key_file, upk_file, ksf_key_file)
    return result

def trapdoor(group_params=group_params, public_params=public_params,
            key_file='key.txt', ksf_key_file='ksf_key.txt', usk_file='usk.txt' , keyword='apple', trapdoor_file='trapdoor.txt'):
    """
    @param group_params: Group parameters file path
    @param public_params: Public parameters file path
    @param key_file: Input decryption key file path
    @param ksf_key_file: Input KSF key file path
    @param usk_file: Input USK file path
    @param keyword: Input keyword string 
    @param trapdoor_file: Output trapdoor file path
    """
    scheme = FENC_SCHEME_KSFCP
    libksf_trapdoor = CDLL(libksf_trapdoor_name)
    result = libksf_trapdoor.generate_trapdoor(scheme, group_params, public_params, key_file, ksf_key_file, usk_file, keyword, trapdoor_file)
    return result

def search(group_params=group_params, public_params=public_params,
            path_file='filepaths.txt', trapdoor_file='trapdoor.txt', result_file='result.txt'):
    """
    @param group_params: Group parameters file path
    @param public_params: Public parameters file path
    @param path_file: Input search data file path
    @param trapdoor_file: Input trapdoor file path
    @param result_file: Output search result file path
    @return: Encrytion status: 0 - OK, not 0 - ERROR
    """
    scheme = FENC_SCHEME_KSFCP
    libksf_search = CDLL(libksf_search_name)
    result = libksf_search.search(scheme, group_params, public_params, path_file, trapdoor_file, result_file)
    return result

def quick_decrypt(group_params=group_params, public_params=public_params,
            input_file='encrypted.txt', key_file='key.txt', usk_file='usk.txt', q_file='encrypted.txt.Q', dec_file='decrypted.txt'):
    """
    @param group_params: Group parameters file path
    @param public_params: Public parameters file path
    @param input_file: Input encrypted file path
    @param key_file: Input decryption key file path
    @param usk_file: Input USK file path
    @param q_file: Input Q data file path
    @param dec_file: Output decrypted file path (with postfix)
    @return: Decrytion status: 0 - OK, not 0 - ERROR
    """
    scheme = FENC_SCHEME_KSFCP
    libabe_qdec = CDLL(libabe_qdec_name)
    result = libabe_qdec.abe_quick_decrypt(scheme, group_params, public_params, input_file, key_file, usk_file, q_file, dec_file)
    return result

# Test cases

def testABE():
    setup()
    keygen(key_string='ONE=58789798, TWO = 20, three')
    
    keywords = 'keywords.txt'
    f = open(keywords, 'w')
    f.write('\n'.join(['apple', 'orange', 'linux', 'fruit', 'ubuntu', 'apple juice', 'pear']))
    f.close()
    
    encrypt(key_string='ONE>2#16  and (2 of (TWO <=20, three, four)) ', data_file='plaintext.txt', keyword_file='keywords.txt')
    decrypt()

def testPolicy():
    print policy_test('one and two or three and (a=1 or b>2 and c<=3)', True)

def testKSF():
    ukeygen()
    ksf_keygen()
    trapdoor(keyword='apple juice')
    
    filepaths = 'filepaths.txt'
    f = open(filepaths, 'w')
    f.write('\n'.join(['encrypted.txt', 'index.txt']))
    f.close()
    
    search()
    quick_decrypt()

# main

if __name__ == '__main__':
    # for test
    testABE()
    testKSF()
    
    
