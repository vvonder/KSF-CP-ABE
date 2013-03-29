from abe_toolkit import *

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
    
    group_params = ['param/a.param', 'param/d224.param']
    
    for g_param in group_params:
        result = []
        for j in range(n_repeat):
            setup(group_params=g_param)
            read_result(result, setup_file)
        avl = avl_result(result)
        print result
        print avl
        tfile.write('%.3f' % avl + '\n') 
    tfile.close()

def test_keygen():
    total_file = 'total_' + keygen_file
    tfile = open(total_file, 'w')
    
    att_strings = ['att' + str(i) for i in range(n_total)]
    for i in range(1, n_total):
        att_strings[i] = att_strings[i - 1] + ',' + att_strings[i]
    
    for att in att_strings:
        result = []
        for j in range(n_repeat):
            keygen(key_string=att)
            read_result(result, keygen_file)
        avl = avl_result(result)
        print result
        print avl
        tfile.write('%.3f' % avl + '\n') 
    tfile.close()

def show_all_results():
    for tfile in test_files:
        print tfile + ':'
        f = open(tfile, 'r')
        print f.read()
        f.close

# main

if __name__ == '__main__':
    # test_setup()
    test_keygen()

