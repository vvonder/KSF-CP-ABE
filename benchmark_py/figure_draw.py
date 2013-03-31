# -*- coding: utf-8 -*-
import os

import matplotlib
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.pylab as pylab
from matplotlib.patches import Polygon
from matplotlib.ticker import MaxNLocator


# result sets path
result_dir = 'results/50x10'

figure_dir = 'figures'

# result files
test_files = [
    "setup.txt",
    "keygen.txt",
    "encrypt.txt",
    "decrypt.txt",
    "ukeygen.txt",
    "ksf_keygen.txt",
    "gen_trapdoor.txt",
    "encrypt_index.txt",
    "search.txt",
    "qdecrypt.txt",
    "random_search.txt",
    "round.txt"
]

# gen total result files path
result_dir = os.path.abspath(result_dir)
figure_dir = os.path.abspath(figure_dir)

total_test_files = [os.path.join(result_dir, ('total_' + i)) for i in test_files]

(setup_file, keygen_file, encrypt_file, decrypt_file, ukeygen_file,
    ksf_keygen_file, gen_trapdoor_file, encrypt_index_file, search_file, qdecrypt_file, random_search_file,
    one_round_file
) = total_test_files

# simsun = matplotlib.font_manager.FontProperties(fname='C:\Windows\Fonts\simsun.ttc')

def read_result(result, result_file):
    f = open(result_file, 'r')
    for line in f.readlines():
        result.append(float(line))
    f.close()

def draw_setup():
    result = []
    read_result(result, setup_file)
    
    N = len(result)
 
    ind = np.arange(N)  # the x locations for the groups
    width = 0.6  # the width of the bars
    
    fig = plt.figure()
    ax = fig.add_subplot(111)
    rects = ax.bar(ind + (width / 2), result, width, color='blue')
    xlabels = ['a', 'd159', 'd201', 'd224', 'e', 'f', 'g149', 'a1']
    
    # add some
    ax.set_ylabel('Time(ms)')
    ax.set_ylim([0, 1000])
    ax.set_title('Setup benchmark')
    ax.set_xticks(ind + width)
    ax.set_xticklabels(xlabels)
    
    # attach some text labels
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width() / 2., height + 10, '%.3f' % height,
                ha='center', va='bottom')

    plt.subplots_adjust(left=0.1, bottom=0.05, right=0.98, top=0.94, wspace=0, hspace=0)
    plt.grid(True, 'major', 'y')
    plt.savefig(os.path.join(figure_dir, 'setup.png'), dpi=150)
    plt.show()

def draw_keygen():
    result = []
    read_result(result, keygen_file)
    
    N = len(result)
    lines = plt.plot(range(1, N + 1), result)

    plt.setp(lines, color='r', marker='o', linestyle='-', linewidth=1.0)
    plt.title('Keygen benchmark')
    plt.xlabel('Num of attributes')
    plt.ylabel('Time(ms)')
    plt.subplots_adjust(left=0.1, bottom=0.1, right=0.98, top=0.94, wspace=0, hspace=0)
    plt.savefig(os.path.join(figure_dir, 'keygen.png'), dpi=150)
    plt.show()

def draw_encrypt():
    result = []
    read_result(result, encrypt_file)
    
    N = len(result)
    lines = plt.plot(range(1, N + 1), result)

    plt.setp(lines, color='r', marker='o', linestyle='-', linewidth=1.0)
    plt.title('Encrypt benchmark')
    plt.xlabel('Num of attributes')
    plt.ylabel('Time(ms)')
    plt.subplots_adjust(left=0.1, bottom=0.1, right=0.98, top=0.94, wspace=0, hspace=0)
    plt.savefig(os.path.join(figure_dir, 'encrypt.png'), dpi=150)
    plt.show()
    
def draw_decrypt():
    result = []
    read_result(result, decrypt_file)
    
    N = len(result)
    lines = plt.plot(range(1, N + 1), result)

    plt.setp(lines, color='r', marker='o', linestyle='-', linewidth=1.0)
    plt.title('Decrypt benchmark')
    plt.xlabel('Num of attributes')
    plt.ylabel('Time(ms)')
    plt.subplots_adjust(left=0.1, bottom=0.1, right=0.98, top=0.94, wspace=0, hspace=0)
    plt.savefig(os.path.join(figure_dir, 'decrypt.png'), dpi=150)
    plt.show()

def draw_index():
    result = []
    read_result(result, encrypt_index_file)
    
    N = len(result)
    lines = plt.plot(range(1, N + 1), result)

    plt.setp(lines, color='r', marker='o', linestyle='-', linewidth=1.0)
    plt.title('Encrypt Index benchmark')
    plt.xlabel('Num of keywords')
    plt.ylabel('Time(ms)')
    plt.subplots_adjust(left=0.1, bottom=0.1, right=0.98, top=0.94, wspace=0, hspace=0)
    plt.savefig(os.path.join(figure_dir, 'index.png'), dpi=150)
    plt.show()

def draw_trapdoor():
    result = []
    read_result(result, gen_trapdoor_file)
    
    N = len(result)
    lines = plt.plot(range(1, N + 1), result)

    plt.setp(lines, color='r', marker='o', linestyle='-', linewidth=1.0)
    plt.title('Gen Trapdoor benchmark')
    plt.xlabel('Num of attributes in SK')
    plt.ylabel('Time(ms)')
    plt.subplots_adjust(left=0.1, bottom=0.1, right=0.98, top=0.94, wspace=0, hspace=0)
    plt.savefig(os.path.join(figure_dir, 'trapdoor.png'), dpi=150)
    plt.show()

def draw_search():
    result = []
    read_result(result, search_file)
    
    N = len(result)
    lines = plt.plot(range(1, N + 1), result)

    plt.setp(lines, color='r', marker='o', linestyle='-', linewidth=1.0)
    plt.title('Search benchmark')
    plt.xlabel('Num of attributes in Trapdoor')
    plt.ylabel('Time(ms)')
    plt.subplots_adjust(left=0.1, bottom=0.1, right=0.98, top=0.94, wspace=0, hspace=0)
    plt.savefig(os.path.join(figure_dir, 'search.png'), dpi=150)
    plt.show()

def draw_random_search():
    result = []
    read_result(result, random_search_file)
    
    N = len(result)
 
    ind = np.arange(N)  # the x locations for the groups
    width = 0.6  # the width of the bars
    
    fig = plt.figure()
    ax = fig.add_subplot(111)
    rects = ax.bar(ind + (width / 2), result, width, color='blue')
    xlabels = range(1, N + 1)
    
    # add some
    ax.set_ylabel('Time(ms)')
    ax.set_ylim([0, 500])
    ax.set_title('Random search benchmark')
    ax.set_xticks(ind + width)
    ax.set_xticklabels(xlabels)
    
    # attach some text labels
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width() / 2., height + 10, '%.3f' % height,
                ha='center', va='bottom')

    plt.subplots_adjust(left=0.1, bottom=0.05, right=0.98, top=0.94, wspace=0, hspace=0)
    plt.grid(True, 'major', 'y')
    plt.savefig(os.path.join(figure_dir, 'random_search.png'), dpi=150)
    plt.show()

def draw_others():
    result = []
    others = [ukeygen_file, ksf_keygen_file, qdecrypt_file]
    for ofile in others:
        r = []
        read_result(r, ofile)
        avl = sum(r) / float(len(r))
        result.append(avl)
    
    N = len(result)
 
    ind = np.arange(N)  # the x locations for the groups
    width = 0.6  # the width of the bars
    
    fig = plt.figure()
    ax = fig.add_subplot(111)
    rects = ax.bar(ind + (width / 2), result, width, color='blue')
    xlabels = ['UKeygen', 'KSF_Keygen', 'QDecrypt']
    
    # add some
    ax.set_ylabel('Time(ms)')
    ax.set_ylim([0, 100])
    ax.set_title('Other function benchmark')
    ax.set_xticks(ind + width)
    ax.set_xticklabels(xlabels)
    
    # attach some text labels
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width() / 2., height + 2, '%.3f' % height,
                ha='center', va='bottom')

    plt.subplots_adjust(left=0.1, bottom=0.05, right=0.98, top=0.94, wspace=0, hspace=0)
    plt.grid(True, 'major', 'y')
    plt.savefig(os.path.join(figure_dir, 'others.png'), dpi=150)
    plt.show()

def draw_one_round():
    f = open(one_round_file, 'r')
    result_s = f.readline()
    f.close()
    
    result = result_s.split(' ')[:-1]
    result = [float(i) for i in result]
    
    
    result[5] += result[4]
    del result[4]
    print result
    
    N = len(result)
    xlabels = ['Setup', 'ABE-KeyGen', 'Encrypt', 'Decrypt',
               'KSF-KeyGen', 'Trapdoor', 'Index', 'Search', 'Q-Decrypt']

#    ind = np.arange(N)  # the x locations for the groups
#    width = 0.6  # the width of the bars
#    
#    fig = plt.figure()
#    ax = fig.add_subplot(111)
#    rects = ax.bar(ind + (width / 2), result, width, color='blue')
#    
#    # add some
#    ax.set_ylabel('Time(ms)')
#    ax.set_ylim([0, 600])
#    ax.set_title('One round benchmark')
#    ax.set_xticks(ind + width)
#    ax.set_xticklabels(xlabels)
#    
#    # attach some text labels
#    for rect in rects:
#        height = rect.get_height()
#        ax.text(rect.get_x() + rect.get_width() / 2., height + 5, '%.3f' % height,
#                ha='center', va='bottom')
#
#    plt.subplots_adjust(left=0.1, bottom=0.05, right=0.98, top=0.94, wspace=0, hspace=0)
#    plt.grid(True, 'major', 'y')
#    plt.savefig(os.path.join(figure_dir, 'one_round.png'), dpi=150)
#    plt.show()
    
    numTests = N
    testNames = xlabels
    testMeta = ['' for i in range(N)]
    scores = result
    rankings = np.round(np.random.uniform(0, 1, numTests) * 100, 0)
    
    fig = plt.figure(figsize=(9, 7))
    ax1 = fig.add_subplot(111)
    plt.subplots_adjust(left=0.13, right=0.88, top=0.94, bottom=0.05)
    fig.canvas.set_window_title('One round benchmark')
    pos = np.arange(numTests) + 0.5  # Center bars on the Y-axis ticks
    rects = ax1.barh(pos, result, align='center', height=0.5, color='b')
    
    ax1.axis([0, 100, 0, N])
    pylab.yticks(pos, testNames)
    ax1.set_title('One round benchmark')

    ax2 = ax1.twinx()
    ax2.plot([100, 100], [0, N], 'white', alpha=0.1)
    
    def withnew(i, scr):
        if testMeta[i] != '' : return '%.3f' % scr
        else: return scr
    scoreLabels = [withnew(i, scr) for i, scr in enumerate(scores)]
    scoreLabels = ['%.3f' % i + j for i, j in zip(scoreLabels, testMeta)]
    pylab.yticks(pos, scoreLabels)
    ax2.set_ylabel('Time(ms)')

    for rect in rects:
        width = rect.get_width()    
        rankStr = str('%.3f' % width) 
        if (width < 50):  # The bars aren't wide enough to print the ranking inside
            xloc = width + 5  # Shift the text to the right side of the right edge
            clr = 'black'  # Black against white background
            align = 'left'
        else:
            xloc = width - 5  # Shift the text to the left side of the right edge
            clr = 'white'  # White on magenta
            align = 'right'
    
        yloc = rect.get_y() + rect.get_height() / 2.0  # Center the text vertically in the bar
        ax1.text(xloc, yloc, rankStr, horizontalalignment=align,
                 verticalalignment='center', color=clr, weight='bold')
    
    plt.savefig(os.path.join(figure_dir, 'one_round.png'), dpi=150)
    plt.show()






def test():
    x = np.linspace(0, 10, 1000)
    y = np.sin(x)
    z = np.cos(x ** 2)
    
    plt.figure(figsize=(8, 4))
    plt.plot(x, y, label="$sin(x)$", color="red", linewidth=2)
    plt.plot(x, z, "b--", label="$cos(x^2)$")
    plt.xlabel("Time(s)")
    plt.ylabel("Volt")
    plt.title("PyPlot First Example")
    plt.ylim(-1.2, 1.2)
    plt.legend()
    plt.show()

# main

if __name__ == '__main__':
    print total_test_files
    # test()
#    draw_setup()
#    draw_keygen()
#    draw_encrypt()
#    draw_decrypt()
#    draw_index()
#    draw_trapdoor()
#    draw_search()
#    draw_random_search()
#    draw_others()
    draw_one_round()


