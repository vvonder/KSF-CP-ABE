import abe_toolkit
import random

test_files = [setup_file, keygen_file, encrypt_file, decrypt_file, ukeygen_file,
    ksf_keygen_file, gen_trapdoor_file, encrypt_index_file, search_file, qdecrypt_file
] = (
    "setup.txt",
    "keygen.txt",
    "encrypt.txt",
    "decrypt.txt",
    "ukeygen.txt",
    "ksf_keygen.txt",
    "gen_trapdoor.txt",
    "encrypt_index.txt",
    "search.txt",
    "qdecrypt.txt"
  )

n_total = 5
n_repeat = 5

def read_result(result, result_file):
    f = open(result_file, 'r')
    for line in f.readlines():
        result_list = line.split(' ')
        result_list.pop()
        result.append(result_list)
    f.close()

def avl_result(result):
    avl = 0
    for r in result:
        count = 0
        for val in r:
            count += float(val)
        avl += count
    avl /= len(result)
    return avl

def test_setup():
    total_file = 'total_' + setup_file
    tfile = open(total_file, 'w')
    
    # Test some type of pairings
    group_params = ['param/a.param', 'param/d224.param']
    
    for g_param in group_params:
        result = []
        for j in range(n_repeat):
            abe_toolkit.setup(group_params=g_param)
            read_result(result, setup_file)
        avl = avl_result(result)
        print result
        print avl
        tfile.write('%.3f' % avl + '\n') 
    tfile.close()

def test_keygen():
    total_file = 'total_' + keygen_file
    tfile = open(total_file, 'w')
    
    # Gen 1 to n_total attributes input
    att_strings = ['att' + str(i) for i in range(n_total)]
    for i in range(1, n_total):
        att_strings[i] = att_strings[i - 1] + ',' + att_strings[i]
    
    abe_toolkit.setup()
    
    for att in att_strings:
        result = []
        for j in range(n_repeat):
            abe_toolkit.keygen(key_string=att)
            read_result(result, keygen_file)
        avl = avl_result(result)
        print result
        print avl
        tfile.write('%.3f' % avl + '\n') 
    tfile.close()

def test_encrypt():
    total_file = 'total_' + encrypt_file
    tfile = open(total_file, 'w')
    
    # Gen data file for encrypt
    data_file = 'plaintext.txt'
    dfile = open(data_file, 'w')
    dfile.write('test')
    dfile.close()
    
    # Gen 1 to n_total 'and' policy input
    policy_strings = ['att' + str(i) for i in range(n_total)]
    for i in range(1, n_total):
        policy_strings[i] = policy_strings[i - 1] + ' and ' + policy_strings[i]
    
    abe_toolkit.setup()
    
    for policy in policy_strings:
        result = []
        for j in range(n_repeat):
            abe_toolkit.encrypt(key_string=policy, data_file=data_file, keyword_file=0)
            read_result(result, encrypt_file)
        avl = avl_result(result)
        print result
        print avl
        tfile.write('%.3f' % avl + '\n') 
    tfile.close()

def test_decrypt():
    total_file = 'total_' + decrypt_file
    tfile = open(total_file, 'w')
    
    # Gen data file for encrypt
    data_file = 'plaintext.txt'
    dfile = open(data_file, 'w')
    dfile.write('test')
    dfile.close()

    # Gen 1 to n_total 'and' policy input
    policy_strings = ['att' + str(i) for i in range(n_total)]
    for i in range(1, n_total):
        policy_strings[i] = policy_strings[i - 1] + ' and ' + policy_strings[i]
    
    # Gen 1 to n_total attributes input
    att_strings = ['att' + str(i) for i in range(n_total)]
    for i in range(1, n_total):
        att_strings[i] = att_strings[i - 1] + ',' + att_strings[i]
    
    abe_toolkit.setup()
    
    for i in range(n_total):
        abe_toolkit.keygen(key_string=att_strings[i])
        abe_toolkit.encrypt(key_string=policy_strings[i], data_file=data_file, keyword_file=0)
        result = []
        for j in range(n_repeat):
            abe_toolkit.decrypt()
            read_result(result, decrypt_file)
        avl = avl_result(result)
        print result
        print avl
        tfile.write('%.3f' % avl + '\n') 
    tfile.close()

def test_ukeygen():
    total_file = 'total_' + ukeygen_file
    tfile = open(total_file, 'w')
    
    abe_toolkit.setup()
    
    result = []
    for j in range(n_repeat):
        abe_toolkit.ukeygen()
        read_result(result, ukeygen_file)
    avl = avl_result(result)
    print result
    print avl
    tfile.write('%.3f' % avl + '\n')
    tfile.close()

def test_ksf_keygen():
    total_file = 'total_' + ksf_keygen_file
    tfile = open(total_file, 'w')
    
    abe_toolkit.setup()
    abe_toolkit.keygen(key_string='att0')
    abe_toolkit.ukeygen()
    
    result = []
    for j in range(n_repeat):
        abe_toolkit.ksf_keygen()
        read_result(result, ksf_keygen_file)
    avl = avl_result(result)
    print result
    print avl
    tfile.write('%.3f' % avl + '\n')
    tfile.close()

def test_trapdoor():
    total_file = 'total_' + gen_trapdoor_file
    tfile = open(total_file, 'w')
    
    # Gen 1 to n_total attributes input
    att_strings = ['att' + str(i) for i in range(n_total)]
    for i in range(1, n_total):
        att_strings[i] = att_strings[i - 1] + ',' + att_strings[i]
    
    abe_toolkit.setup()
    abe_toolkit.ukeygen()
    
    for i in range(n_total):
        abe_toolkit.keygen(key_string=att_strings[i])
        abe_toolkit.ksf_keygen()
        result = []
        for j in range(n_repeat):
            abe_toolkit.trapdoor(keyword='apple juice')
            read_result(result, gen_trapdoor_file)
        avl = avl_result(result)
        print result
        print avl
        tfile.write('%.3f' % avl + '\n') 
    tfile.close()

def test_index():
    total_file = 'total_' + encrypt_index_file
    tfile = open(total_file, 'w')
    
    # Gen data file for encrypt
    data_file = 'plaintext.txt'
    dfile = open(data_file, 'w')
    dfile.write('test')
    dfile.close()
    
    keyword_file = 'keywords.txt'
    
    # Gen 1 to n_total keyword input
    keyword_strings = ['keyword' + str(i) for i in range(n_total)]
    for i in range(1, n_total):
        keyword_strings[i] = keyword_strings[i - 1] + '\n' + keyword_strings[i]
    
    abe_toolkit.setup()
    
    for keywords in keyword_strings:
        # Gen keyword list file for encrypt
        dfile = open(keyword_file, 'w')
        dfile.write(keywords)
        dfile.close()

        result = []
        for j in range(n_repeat):
            abe_toolkit.encrypt(key_string='att0', data_file=data_file, keyword_file=keyword_file)
            read_result(result, encrypt_index_file)
        avl = avl_result(result)
        print result
        print avl
        tfile.write('%.3f' % avl + '\n') 
    tfile.close()

def test_search():
    total_file = 'total_' + search_file
    tfile = open(total_file, 'w')
    
    # Gen data file for encrypt
    data_file = 'plaintext.txt'
    dfile = open(data_file, 'w')
    dfile.write('test')
    dfile.close()

    # Gen 1 to n_total 'and' policy input
    policy_strings = ['att' + str(i) for i in range(n_total)]
    for i in range(1, n_total):
        policy_strings[i] = policy_strings[i - 1] + ' and ' + policy_strings[i]
    
    # Gen 1 to n_total attributes input
    att_strings = ['att' + str(i) for i in range(n_total)]
    for i in range(1, n_total):
        att_strings[i] = att_strings[i - 1] + ',' + att_strings[i]
    
    # Gen filepaths for search
    filepaths = 'filepaths.txt'
    f = open(filepaths, 'w')
    f.write('\n'.join(['encrypted.txt', 'index.txt']))
    f.close()
    
    # Gen n_total keyword input
    keyword_strings = ['keyword' + str(i) for i in range(n_total)]
    
    keyword_file = 'keywords.txt'
    f = open(keyword_file, 'w')
    f.write('\n'.join(keyword_strings))
    f.close()
    
    abe_toolkit.setup()
    abe_toolkit.ukeygen()
    
    for i in range(n_total):
        abe_toolkit.keygen(key_string=att_strings[i])
        abe_toolkit.ksf_keygen()
        abe_toolkit.trapdoor(keyword=keyword_strings[-1])
        abe_toolkit.encrypt(key_string=policy_strings[i], data_file=data_file, keyword_file=keyword_file)
       
        result = []
        for j in range(n_repeat):
            abe_toolkit.search()
            read_result(result, search_file)
        avl = avl_result(result)
        print result
        print avl
        tfile.write('%.3f' % avl + '\n') 
    tfile.close()

def test_qdecrypt():
    total_file = 'total_' + qdecrypt_file
    tfile = open(total_file, 'w')
    
    # Gen data file for encrypt
    data_file = 'plaintext.txt'
    dfile = open(data_file, 'w')
    dfile.write('test')
    dfile.close()

    # Gen 1 to n_total 'and' policy input
    policy_strings = ['att' + str(i) for i in range(n_total)]
    for i in range(1, n_total):
        policy_strings[i] = policy_strings[i - 1] + ' and ' + policy_strings[i]
    
    # Gen 1 to n_total attributes input
    att_strings = ['att' + str(i) for i in range(n_total)]
    for i in range(1, n_total):
        att_strings[i] = att_strings[i - 1] + ',' + att_strings[i]
    
    # Gen filepaths for search
    filepaths = 'filepaths.txt'
    f = open(filepaths, 'w')
    f.write('\n'.join(['encrypted.txt', 'index.txt']))
    f.close()
    
    keyword_file = 'keywords.txt'
    f = open(keyword_file, 'w')
    f.write('apple')
    f.close()
    
    abe_toolkit.setup()
    abe_toolkit.ukeygen()
    
    for i in range(n_total):
        abe_toolkit.keygen(key_string=att_strings[i])
        abe_toolkit.ksf_keygen()
        abe_toolkit.trapdoor(keyword='apple')
        abe_toolkit.encrypt(key_string=policy_strings[i], data_file=data_file, keyword_file=keyword_file)
        abe_toolkit.search()
       
        result = []
        for j in range(n_repeat):
            abe_toolkit.quick_decrypt()
            read_result(result, qdecrypt_file)
        avl = avl_result(result)
        print result
        print avl
        tfile.write('%.3f' % avl + '\n') 
    tfile.close()

def test_random_search():
    total_file = 'total_random_' + search_file
    tfile = open(total_file, 'w')
    
    # Gen data file for encrypt
    data_file = 'plaintext.txt'
    dfile = open(data_file, 'w')
    dfile.write('test')
    dfile.close()

    # Gen 1 to n_total 'and' policy input
    policy_strings = ['att' + str(i) for i in range(n_total)]
    for i in range(1, n_total):
        policy_strings[i] = policy_strings[i - 1] + ' and ' + policy_strings[i]
    
    # Gen half n_total attributes input, this user can decrypt half above policys ciphertexts
    att_string = ['att' + str(i) for i in range(n_total / 2)]

    # Gen n_total keyword input
    keyword_strings = ['keyword' + str(i) for i in range(n_total)]
    
    keyword_file = 'keywords.txt'
    f = open(keyword_file, 'w')
    f.write('\n'.join(keyword_strings))
    f.close()
    
    abe_toolkit.setup()
    abe_toolkit.ukeygen()
    abe_toolkit.keygen(key_string=','.join(att_string))
    abe_toolkit.ksf_keygen()
    abe_toolkit.trapdoor(keyword=keyword_strings[-1])
  
    # Encrypt files
    for i in range(n_total):
        enc_file = 'encrypted' + str(i) + '.txt'
        index_file = 'index' + str(i) + '.txt'
        abe_toolkit.encrypt(key_string=policy_strings[i], data_file=data_file, keyword_file=keyword_file,
                            enc_file=enc_file, index_file=index_file)

    # Random gen filepaths and search
    filepaths = 'filepaths.txt'
 
    result = [] 
    for j in range(n_repeat):
        f = open(filepaths, 'w')
        num_list = range(n_total)
        random.shuffle(num_list)
        for k in num_list:
            enc_file = 'encrypted' + str(k) + '.txt'
            index_file = 'index' + str(k) + '.txt'
            f.write('\n'.join([enc_file, index_file, '']))
        f.close()
        
        abe_toolkit.search()
        read_result(result, search_file)
        avl = avl_result(result)
        print result
        print avl
        tfile.write('%.3f' % avl + '\n') 
    tfile.close()

# main

if __name__ == '__main__':
    test_setup()
    test_keygen()
    test_encrypt()
    test_decrypt()
    
    test_ukeygen()
    test_ksf_keygen()
    test_trapdoor()
    test_index()
    test_qdecrypt()
    test_search()
    test_random_search()

