import configparser
import deepdiff
import difflib
import frontmatter
import hashlib
import io
import os
import random
import re
import zoneinfo

from collections import Counter
from datetime import date
from datetime import datetime
from os.path import basename
from pprint import pprint
from re import split


import json

flashcard_sys = 'anki'
flashcard_sys = 'flashcards'

fn_prefix = '_NEW_'

rgx_html_comment = re.compile(r'<!--.*?-->', re.DOTALL)

rgx_QA_exclude       = None
rgx_QA_pattern       = None
rgx_QA_DECK          = None
rgx_d8_hash          = None
rgx_QA_startword     = None
rgx_QA_block         = None
rgx_QA_split         = None
rgx_QA_ID            = None          # tacID: unique identifier of QA + deck
rgx_QA_SR_hash       = None          # hash of deck + s_QA
rgx_html_comment     = None          # Regex that matches HTML comments (including multiline)
rgx_flashcard_backup = None
rgx_norm_QA_deck     = None

def load_config(ini_path):
    global rgx_QA_exclude
    global rgx_QA_pattern
    global rgx_QA_DECK
    global rgx_d8_hash
    global rgx_QA_startword
    global rgx_QA_block
    global rgx_QA_split
    global rgx_QA_ID
    global rgx_QA_SR_hash
    global rgx_html_comment
    global rgx_flashcard_backup
    global rgx_norm_QA_deck

    config = configparser.ConfigParser()
    config.read(ini_path)

    p_root   = config['DEFAULT']['p_root']
    ext      = config['DEFAULT']['ext']
    p_QA     = config['DEFAULT']['p_QA']
    QA_tag   = config['DEFAULT']['QA_tag']

    rgx_QA_exclude   = re.compile(config['DEFAULT']['rgx_QA_exclude'], re.MULTILINE | re.DOTALL)
    rgx_QA_DECK      = re.compile(config['DEFAULT']['rgx_QA_DECK'], re.MULTILINE | re.DOTALL)
    rgx_d8_hash      = re.compile(config['DEFAULT']['rgx_d8_hash'], re.MULTILINE | re.DOTALL)
    rgx_QA_ID        = re.compile(config['DEFAULT']['str_QA_ID'])
    rgx_html_comment = re.compile(r'<!--.*?-->', re.DOTALL)

    QA_lo_start_tag  = ["#QA", "#flashards"]
    lo_startword_raw = ['#flashcards', '#QA']
    lo_QA_startword  = [re.escape(sw) for sw in lo_startword_raw]
    s_startword_tail = r"[A-Za-z0-9_/\-\\]{0,25}"
    lo_stopword_raw  = list(lo_startword_raw).append(['Quelle: '])

    rgx_QA_startword = r"(?:%s)%s" % ("|".join(lo_QA_startword), s_startword_tail)

    rgx_html_comment = re.compile(r"<!--.*?-->", re.DOTALL)
    rgx_QA_SR_hash   = re.compile(r"([A-Z0-9]{8})(?:_(\d{3}))?(?:_(\d{8}))?")


    # Escape each tag so '#' and other characters become literal.
    rgx_QA_lo_start_tag = "|".join(re.escape(tag) + r"_[A-Za-z0-9._-]+" for tag in QA_lo_start_tag)  # tag + file-safe chars

    # Compile begin-regex (still matches only at the beginning of a line)
    rgx_QA_block_begin = re.compile(rf"^(?:{rgx_QA_lo_start_tag})", re.MULTILINE)

    QA_lo_stop_tag = ["Quelle: ", "source: "]

    # Combine:
    # - fixed stopword lines (escaped)
    # - block-begin lines as QA_lo_stop_tag (so a new block ends the previous one)
    rgx_QA_lo_stop_tag = "|".join([re.escape(w) for w in QA_lo_stop_tag] + [rgx_QA_lo_start_tag])

    # MAIN BLOCK EXTRACTION REGEX
    rgx_QA_block = re.compile(
        rf"""
        (?P<begin> {rgx_QA_block_begin.pattern}   # block starts here
        )
        (?P<body>  .*?                            # non-greedy body text
        )
        (?= ^(?:{rgx_QA_lo_stop_tag})             # stop BEFORE stopword/next block
        )
        """,
        re.DOTALL | re.MULTILINE | re.VERBOSE
    )

    rgx_QA_pattern = rgx_QA_block

    # Split QA in Q and A
    rgx_QA_split = re.compile(
        r'^'
        r'(?P<QA_Q>.*?)'  # non-greedy: content before separator
        r'(?:'
        r'(?=\nA:\s)'  # A: separator → lookahead (keep it!)
        # r'|' r'\n?\n'  # blank line
        r'|' r'\n\?\n'  # line with ?
        r'|' r'\n\?\?\n'  # line with ??
        r'|' r':::'  # :::
        r'|' r'::'  # ::
        r')'
        r'(?P<QA_A>.*)'  # Answer part, includes A: when present
        r'$',
        re.DOTALL
    )

    rgx_flashcard_backup = re.compile(
        r"""
        \.                # literal dot
        \d{4}-\d{2}-\d{2} # YYYY-MM-DD
        (?:_\d{2})?       # optional _hh (two digits)
        (?:_\d{2})?       # optional _mm (two digits)
        $                 # end of string
        """,
        re.VERBOSE,
    )

    # Flashcard tags: or '#flashcards' or some user defined tag.
    # We use: '#flashcards' or 'QA_*'. Something like '#QA_myQuestion' will
    # be splitted into: '#QA/myQuestion'
    rgx_norm_QA_deck = re.compile(r"^(#QA)_([A-Za-z0-9/_-]+)$", flags=re.IGNORECASE)

    return p_root, ext, p_QA, QA_tag


def generate_random_hash(length=8):
    return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789', k=length))

def get_cleaned_line(line):
    # clean line from whitespaces; purge horizontal lines.
    if not line.strip():
        return False
    if re.search(r"-{3,}", line):  # r"-{3,}" == horizontal line
        return False
    if re.search(r"_{3,}", line):  # r"_{3,}" == horizontal line
        return False
    return True

def get_lo_QA_deck_block(text):
    # QA_deck_block == block of text ...
    # ... beginning with tag indicating deck of one or more following QAs.

    lo_QA_deck_block = []
    matches = [block.group() for block in rgx_QA_block.finditer(text)]
    if not matches:
        return []

    for idx, block_text in enumerate(matches):

        # for example: #ToDo_QA
        if rgx_QA_exclude.search(block_text):
            continue

        lines = block_text.splitlines()

        deck_line = lines[0]
        qa_lines  = lines[1:]

        deck_clean = "\n".join(ln for ln in [deck_line] if get_cleaned_line(ln))
        qa_clean   = "\n".join(ln for ln in qa_lines    if get_cleaned_line(ln))

        # list of decks
        lo_QA_deck = re.findall(rgx_QA_startword, deck_clean)

        lo_QA_deck_block.append({
            "DECK": deck_clean,
            "QA": qa_clean,
            "lo_QA_deck": lo_QA_deck
        })

    return lo_QA_deck_block


def get_lo_d_QA(QA_deck_block):
    # >QA_deck_block< == line containing one or more >deck< entries followed by QA text without >deck< entries.
    # Transform textblock into cartesian product (lo of dict): item == every deck with every QA_text.

    QA_text, lo_QA_deck = QA_deck_block["QA"], QA_deck_block["lo_QA_deck"]
    positions = [m.start() for m in re.finditer(r"^Q: ", QA_text, re.MULTILINE)]
    if not positions:
        return []

    positions.append(len(QA_text))

    lo_s_QA = []
    for i in range(len(positions) - 1):
        start = positions[i]
        end = positions[i + 1]
        chunk = QA_text[start:end].strip()
        if chunk:
            lo_s_QA.append(chunk)

    lo_d_QA = []
    for deck in lo_QA_deck:
        for s_QA in lo_s_QA:
            lo_d_QA.append({
                "QA_deck": deck,
                "s_QA": s_QA
            })
    return lo_d_QA


def get_d8_hash(s_in):
    # calcs SHA256 hash of QA_A and returns last 8 characters as string
    h = hashlib.sha256(s_in.encode("utf-8")).hexdigest()
    return h[-8:]


def get_QA_Q_and_A(s_QA):
    # split s_QA in Q and A
    m = rgx_QA_split.match(s_QA)
    if m:
        QA_Q = m.group("QA_Q").strip()
        QA_A = m.group("QA_A").strip()
    else:
        QA_Q = s_QA.strip()
        QA_A = ""

    return QA_Q, QA_A

def get_QA_ID(QA_A):
    #
    matches = []

    for m in rgx_QA_ID.finditer(QA_A):
        qa_string = m.group(0)
        # print("get_QA_ID: QA_ID = ", qa_string)

        matches.append({
            'QA_string': qa_string,
            'prefix': m.group("prefix"),
            'z_hash': m.group("z_hash"),
            'QA_deck_hash': m.group("QA_deck_hash")
        })
        return matches[0]['QA_string']
    else :
        return None

def b_test_do_QA(do_QA):

    s_QA_deck     = do_QA["QA_deck"]
    s_QA          = do_QA["QA"]
    s_QA_d8_hash  = do_QA["QA_d8_hash"]

    s_deck_and_QA = do_QA["QA_deck"] + ' - ' + s_QA
    QA_d8_hash    = get_d8_hash(s_deck_and_QA)
    QA_ID         = get_QA_ID(s_QA)

    return (QA_d8_hash == s_QA_d8_hash)



def get_normalized_QA_deck(s_QA_deck):
    # normalize QA_deck: Obsidian Plugin Spaced Repetition demands as

    # If >s_QA_deck< begins with: '#flashcards'
    if s_QA_deck.startswith("#flashcards"): return s_QA_deck

    s_QA_deck = re.sub(r"_+", "_", s_QA_deck)
    m = re.match(rgx_norm_QA_deck, s_QA_deck)
    if m:
        # Replace first "_" after the prefix with "/"
        print(s_QA_deck, m.group(1))
        return f"{m.group(1)}/{m.group(2)}"
    else:
        return f"#flashcards/{s_QA_deck}[1:]"

def get_normalized_lo_d_QA(lo_do_QA, file_path, fn, QA_zotero_hash):
    # in s_QA:
    # extract and purge html comments and hashes
    # normalize Spaced Repetition tag

    lo_do_QA_normalized = []
    for do_QA in lo_do_QA:
        s_QA = do_QA["s_QA"]

        # Purge HTML comments and old hash-like strings
        # s_clean = rgx_html_comment.sub("", s_QA)
        # s_clean = rgx_QA_SR_hash.sub("", s_clean)
        # s_clean = rgx_QA_ID.sub("", s_clean)
        # s_QA    = s_clean.strip()

        # Extract QA_TimeStamp ( is in HTML comment )
        m_comment    = rgx_html_comment.search(s_QA)
        QA_TimeStamp = m_comment.group(0) if m_comment else None

        # Purge HTML comments from s_QA
        s_QA       = rgx_html_comment.sub("", s_QA)
        s_QA       = s_QA.strip()

        # get Q & A
        QA_Q, QA_A = get_QA_Q_and_A(s_QA)

        # normalize Spaced Repetition tag:
        qa_tag     = get_normalized_QA_deck(do_QA["QA_deck"])

        do_QA["QA_deck"] = qa_tag
        # do_QA["QA_deck"] = get_normalized_QA_deck(do_QA["QA_deck"])
        # If there is no "QA_ID" at the end of QA_A
        s_deck_and_QA = do_QA["QA_deck"] + ' - ' + s_QA
        QA_d8_hash = get_d8_hash(s_deck_and_QA)
        QA_ID = get_QA_ID(s_QA)

        m_QA_ID = rgx_QA_ID.search(s_QA)
        QA_ID   = m_QA_ID.group(0) if m_QA_ID else None

        if not QA_ID:
            # Compute new deterministic hash == ID from original s_QA combining QA-text and deck.
            QA_ID = '(' + 'QA_ID_' + QA_zotero_hash + '_' + QA_d8_hash + ')'  # specific ID of QA + deck.

        # Build normalized dict
        do_QA = {
            'path'           : file_path,        # path
            'fn'             : fn,               # filename
            "QA_deck"        : do_QA["QA_deck"], # deck of QA
            "QA"             : s_QA,             # complete string of QA
            "QA_Q"           : QA_Q,             # Question
            "QA_A"           : QA_A,             # Answer
            "QA_TimeStamp"   : QA_TimeStamp,     # timestamp of Spaced Repetition obsidian plugin
            "QA_zotero_hash" : QA_zotero_hash,   # hash of note (from frontmatter but where does it come from ??)
            "QA_d8_hash"     : QA_d8_hash,       # hash of specific question QA_deck included
            "QA_ID"          : QA_ID             # specific ID of QA + deck.
                                                 # if >QA_d8_hash< != third part of  >QA_ID<   => >QA< ond/or deck has changed.
        }

        if b_test_do_QA(do_QA):
            lo_do_QA_normalized.append(do_QA)

    return lo_do_QA_normalized

def calc_d8_hash(s_qa_block) -> str:
    # calc sha256-hash of >s_qa_block< & return last 8 chars of hash.
    # - escape special chars
    s_qa_block = re.escape(s_qa_block)
    # - eliminate consecutive whitespaces >s_qa_block<
    s_qa_block = re.sub(r'\s+', ' ', s_qa_block)
    # - encode UTF-8
    s_qa_block = s_qa_block.encode('utf-8')
    # - encode UTF-8
    hash_int = int(hashlib.sha256(s_qa_block).hexdigest(), 16)
    # - Convert the hexadecimal to an integer hash string
    d8_hash_calc = str(hash_int)[-8:]

    # or kick it like Perplexity: !
    #   Use the modulo operator (%) to keep only the last 8 digits
    #   10**8 is 100,000,000
    #   d8_hash = hash_int % (10 ** 8)
    return d8_hash_calc


def find_files_with_extension(root, extension):
    matches = []
    for current_dir, _, filenames in os.walk(root):
        for fname in filenames:
            if fname.endswith(extension):
                matches.append(os.path.normpath(os.path.join(current_dir, fname)))
    return matches


def get_l_s_QA_deck(content, rgx_QA_DECK, fixed_QA_prefix):
    deck_matches = rgx_QA_DECK.findall(content)
    lo_QA_deck = [m[len(fixed_QA_prefix) + 1:] if m.startswith(fixed_QA_prefix) else m for m in deck_matches]
    if len(lo_QA_deck) == 0:
        lo_QA_deck = ['Default']
    return lo_QA_deck


def files_are_identical(new_file_path, content2):
    if not os.path.isfile(new_file_path):
        return False
    with open(new_file_path, 'r', encoding='utf-8') as f1:
        content1 = f1.read()
    return content1 == content2

def get_QA_zotero_hash_from_frontmatter(file_path, metadata: dict[str, object], post, rgx_QA_SR_hash) -> str:
    # QA_zotero_hash == frontmatter['san']['zotero_hash'] ... to identify note or zotero annotation.
    # Serves to create a unique ID of QA. If not present then will be generated.
    QA_SR_hash = None
    if 'san' in metadata and isinstance(metadata['san'], dict):
        candidate = metadata['san'].get('zotero_hash')
        if candidate and rgx_QA_SR_hash.search(candidate):
            QA_SR_hash = candidate

    if not QA_SR_hash:
        # fake: ['san']['zotero_hash']
        QA_SR_hash = generate_random_hash()
        if 'san' not in metadata or not isinstance(metadata['san'], dict):
            metadata['san'] = {}
        metadata['san']['zotero_hash'] = QA_SR_hash
        post.metadata = metadata
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(frontmatter.dumps(post))
    return QA_SR_hash

def get_lo_all_QA_hashes(content: str, rgx_QA_SR_hash) -> list:
    if flashcard_sys == 'anki':
        lo_all_QA_hashes = rgx_QA_SR_hash.findall(content)
    elif flashcard_sys == 'flashcards':
        # In
        lo_html_comment  = rgx_html_comment.findall(content)
        lo_all_QA_hashes = []
        for html_comment in lo_html_comment:
            if rgx_QA_SR_hash.findall(html_comment):
                lo_all_QA_hashes += rgx_QA_SR_hash.findall(html_comment)
    else:
        exit('get_lo_all_QA_hashes(): flashcard_sys?')
    return lo_all_QA_hashes



def get_lo_s_QA(content: str) -> list[str]:
    # from *.md notes get QA. Transform them into a flashcard file (obsidian Spaced Repetition / anki ?)
    if flashcard_sys == 'flashcards':

        iter_QA_match  = rgx_QA_pattern.finditer(content)
        for QA_match in iter_QA_match:
            if QA_match:
                s_lo_QA_deck = QA_match.group('rgx_lo_QA_deck')
                QA_Question  = QA_match.group('QA_Question')
                QA_type      = QA_match.group('QA_type')
                QA_Answer    = QA_match.group('QA_Answer')
                lo_QA_deck   = s_lo_QA_deck.split(' ')
            else:
                return None

        l_qa_match = rgx_QA_pattern.findall(content)
        # get_tu_Q_A_part(qa_string)
        lo_s_qa = []
        if l_qa_match and isinstance(l_qa_match[0], tuple):
            # lo_s_qa = [''.join(m) for m in l_qa_match]
            for qa_match in l_qa_match:
                lo_s_qa.append(qa_match)
        else:
            lo_s_qa = l_qa_match
        return lo_s_qa
    else:
        exit('get_lo_all_QA_hashes(): flashcard_sys?')

def get_normalized_s_qa_block(s_qa: str) -> str:
    s_qa_block = ''.join(s_qa)
    if not s_qa_block.endswith('\n'):
        s_qa_block += '\n'
    s_qa_block = re.escape(s_qa_block)
    return s_qa_block

def get_lo_qa_entry_vs_01(file_paths):
    # return list of all QA-entries in note: qa_entry.QA, possibly qa_entry.QA_SR_hash, qa_entry.QA_deck
    lo_qa_entry = []
    # Get frontmatter of note
    for file_path in file_paths:
        fn = os.path.basename(file_path)
        try:
            post = frontmatter.load(file_path)
            content_io = io.StringIO(post.content)
            content = content_io.read()
        except Exception as e:
            print(f"Warning: Could not load frontmatter from {file_path}: {e}")
            continue

        # for example: #ToDo_QA
        if rgx_QA_exclude.search(content):
            continue

        # Pattern of QA
        QA_matches =  rgx_QA_pattern.finditer(content)
        if not QA_matches:
            continue

        # Anki: Deck
        fixed_QA_prefix = "#QA_DECK_"
        lo_QA_deck = get_l_s_QA_deck(content, rgx_QA_DECK, fixed_QA_prefix)

        # Get from frontmatter: QA_SR_hash
        metadata = post.metadata
        QA_SR_hash =  get_QA_zotero_hash_from_frontmatter(file_path, metadata, post, rgx_QA_SR_hash)

        # Get QA-text_blocks in note - maybe multiple QA'QA_A, hence list.
        lo_s_qa = get_lo_s_QA(content)

        # note may possibly be modified (by inserting QA_SR_hash to QA)
        modified_content = content
        multiple_matches = len(lo_s_qa) > 1

        # QA-text_blocks possibly have already QA_SR_hash -> make list of them
        lo_all_QA_hashes = get_lo_all_QA_hashes(content, rgx_QA_SR_hash)

        # ???
        # lo_qa_hash = [''] * len(lo_s_qa)

        # For every QA-text_block
        for idx, s_qa in enumerate(lo_s_qa):
            s_qa_block = get_normalized_s_qa_block(s_qa)
            s_qa_d8_hash_calc = calc_d8_hash(s_qa_block)
            s_qa_d8_hash = rgx_d8_hash.search(s_qa_block)
            if not s_qa_d8_hash or (s_qa_d8_hash != s_qa_d8_hash_calc):
                s_qa_d8_hash = s_qa_d8_hash_calc

                if multiple_matches:
                    candidate_idx = idx
                    QA_hash_idx = f'{QA_SR_hash}_{candidate_idx:03d}'
                    while QA_hash_idx in lo_all_QA_hashes:
                        candidate_idx += 1
                        QA_hash_idx = f'{QA_SR_hash}_{candidate_idx:03d}_{s_qa_d8_hash}'

                    insert_str = f'({QA_hash_idx}_{s_qa_d8_hash})\n'
                else:
                    insert_str = f'({QA_SR_hash}_{s_qa_d8_hash})\n'

                modified_content = re.sub(
                    rf'({s_qa_block})',
                    rf'\1{insert_str}',
                    modified_content,
                    count=1
                )
                # modify A: attaching index (oder hash von s_qa_block?)
                # lo_s_qa[idx][0] = lo_s_qa[idx][0] + '\n' + insert_str
                s_qa_new = (lo_s_qa[idx][0], lo_s_qa[idx][1] + '\n' + insert_str)
                lo_s_qa[idx] = s_qa_new
                # lo_qa_hash[idx-1] = QA_SR_hash

        orig_dir = os.path.dirname(file_path)
        base_name = os.path.basename(file_path)

        if base_name.startswith(fn_prefix):
            new_filename = base_name
        else:
            new_filename = fn_prefix + base_name

        new_file_path = os.path.normpath(os.path.join(orig_dir, new_filename))

        fm_text = frontmatter.dumps(post)
        split_index = fm_text.find('---', 3)
        if split_index == -1:
            frontmatter_header = fm_text
        else:
            frontmatter_header = fm_text[:split_index + 3]

        full_new_content = frontmatter_header + '\n' + modified_content

        if os.path.exists(new_file_path):
            if not os.path.isfile(new_file_path):
                return False
            with open(new_file_path, 'r', encoding='utf-8') as new_f:
                new_content = new_f.read()

            differ  = difflib.Differ()
            delta_x = list(differ.compare(new_content.splitlines(), full_new_content.splitlines()))
            delta   = "\n".join(delta_x)
            if new_content == full_new_content:
                print(f"File identical, skipping overwrite: {new_file_path}")
            else:
                with open(new_file_path, 'w', encoding='utf-8') as f_new:
                    f_new.write(full_new_content)
                print(f"File updated: {new_file_path}")
            if new_file_path in file_paths:
                file_paths.remove(new_file_path)
        else:
            with open(new_file_path, 'w', encoding='utf-8') as f_new:
                f_new.write(full_new_content)
            print(f"File written: {new_file_path}")

        for s_QA in lo_s_qa:
            for QA_deck in lo_QA_deck:
                s_qa = re.search(rgx_QA_SR_hash, s_QA[1])
                QA_SR_hash = s_qa.group(0) if s_qa else ''
                qa_entry = {
                    'QA_deck': QA_deck,
                    'QA_SR_hash': QA_SR_hash,
                    's_QA': s_QA,
                    # 'path': file_path,
                    'path': fn,
                }
                lo_qa_entry.append(qa_entry)
    return lo_qa_entry


def get_lo_QA_file(file_paths):
    # return list of file_paths that contain QA - text blocks.
    lo_do_QA_files = []
    for file_path in file_paths:
        fn = os.path.basename(file_path)
        try:
            post = frontmatter.load(file_path)
            content_io = io.StringIO(post.content)
            content = content_io.read()
        except Exception as e:
            print(f"Warning: Could not load frontmatter from {file_path}: {e}")
            continue

        # Pattern of QA
        QA_matches =  rgx_QA_pattern.finditer(content)
        if not QA_matches:
            continue

        d_QA_file = dict()
        d_QA_file['fn']      = fn
        d_QA_file['path']    = file_path
        d_QA_file['post']    = post
        d_QA_file['content'] = content
        lo_do_QA_files.append(d_QA_file)
    return lo_do_QA_files


def get_lo_qa_entry(file_paths):
    # return list of all QA-entries in note: qa_entry.QA, possibly qa_entry.QA_zotero_hash, qa_entry.QA_deck
    # >lo_do_QA_file< list of all files with QA section.
    lo_do_QA_file      = get_lo_QA_file(file_paths)

    lo_do_QA_entry     = []
    for do_QA_file in lo_do_QA_file:
        # QA == Question-Answer text .
        file_path      = do_QA_file['path']
        fn             = do_QA_file['fn']
        content        = do_QA_file['content']
        post           = do_QA_file['post']

        metadata       = post.metadata
        QA_zotero_hash = get_QA_zotero_hash_from_frontmatter(file_path, metadata, post, rgx_QA_SR_hash)

        # QA_deck_block == block of text beginning with tag indicating deck of one or more QAs.
        lo_QA_deck_block = get_lo_QA_deck_block(content)

        # >lo_do_QA_entry_org< == raw QA text block as is (with Timestamp, Anki-, obsidian- ID or similar ...)
        # Will be cleaned from that. --> >lo_do_QA_entry<
        lo_do_QA_entry_org = []
        # transform multiple QA textblock in multiple dicts of QA: "QA_deck": ..., "s_QA": ...
        for QA_deck_block in lo_QA_deck_block:
            lo_do_QA_entry_org.extend(get_lo_d_QA(QA_deck_block))

        # normalize every d_QA and add hash of Text of QA
        # Normalize and clean QA from Timestamp of Spaced Repetition and ID of tac.py and ...
        # ... add: file_path, fn, QA_zotero_hash
        lo_do_QA_entry.extend(get_normalized_lo_d_QA(lo_do_QA_entry_org, file_path, fn, QA_zotero_hash))
    return lo_do_QA_entry


def get_lo_do_QA_flashcard(lo_p_fn_flashcard):
    # get all entries in Spaced Repetition obsidian note.
    # get >lo_flashcard< == all Q&As

    lo_flashcard       = []
    lo_QA_deck_block   = []
    lo_do_QA_flashcard = []
    lo_do_QA_entry_org = []

    # With every file containing flashcard style QAs:
    for p_fn_flashcard in lo_p_fn_flashcard:
        with open(p_fn_flashcard, 'r', encoding='utf-8') as f:
            qa_file_text = f.read()

        # Split s_text into blocks by lines starting with #flashcards (keep markers)
        lo_block_text = re.split(r'(?=^#flashcards[^\n]*)', qa_file_text, flags=re.MULTILINE)

        # file may contain more than one QA blocks.
        # Block == one or more decks on first line
        #          followed by one or more QA that may be on one or more lines.
        for block_text in lo_block_text:
            lines = block_text.strip().splitlines()
            if not lines:
                continue

            # First line is the deck line (contains #flashcards and tags)
            deck_line = lines[0]
            # QA - lines:
            qa_lines  = lines[1:]

            deck_clean = "\n".join(ln for ln in [deck_line] if get_cleaned_line(ln))
            qa_clean   = "\n".join(ln for ln in qa_lines if get_cleaned_line(ln))

            # get all deck tags
            lo_QA_deck = re.findall(rgx_QA_startword, deck_clean)

            lo_QA_deck_block.append({
                "DECK": deck_clean,
                "QA": qa_clean,
                "lo_QA_deck": lo_QA_deck
            })

            # >lo_do_QA_entry_org< == raw QA text block as is (with Timestamp, Anki-, obsidian- ID or similar ...)
            # Will be cleaned from that. --> >lo_do_QA_flashcard<
            lo_do_QA_entry_org = []
            # transform multiple QA textblock in multiple dicts of QA: "QA_deck": ..., "s_QA": ...
            for QA_deck_block in lo_QA_deck_block:
                lo_do_QA_entry_org.extend(get_lo_d_QA(QA_deck_block))

            # file_path = p_fn_flashcard
            # fn = os.path.basename(file_path)
        if lo_do_QA_entry_org:
            lo_do_QA_flashcard.extend(get_normalized_lo_d_QA(lo_do_QA_entry_org, file_path = p_fn_flashcard, fn = os.path.basename(p_fn_flashcard), QA_zotero_hash ='flashcar'))
    return lo_do_QA_flashcard


def get_lo_p_fn_flashcard(QA_tag, p_QA):
    # return list of path of every *.md file that contains  Q&A's in flashcard (== Spaced Repetition) format.
    lo_p_fn_qa = []
    for root, _, files in os.walk(p_QA):
        for fname in files:
            if fname.endswith('.md') and not b_filter_backup_flashcard_file(fname, '.md'):
                p_fn = os.path.normpath(os.path.join(root, fname))
                with open(p_fn, 'r') as f:
                    first_line = f.readline()
                    if first_line.startswith(QA_tag):
                        lo_p_fn_qa.append(p_fn)
    return lo_p_fn_qa


def get_merge_lo_do_QA(lo_do_qa_entry, lo_do_QA_flashcard):
    # Make list of all different QA in two lists: lo_do_qa_entry, lo_do_QA_flashcard
    # Add both lists and then purge duplicates, if any:

    lo_QA_out = []

    lo_QA_out = lo_do_QA_flashcard + lo_do_qa_entry
    lo_QA_out = sort_and_clear_lo_do_QA(lo_QA_out)
    return lo_QA_out

def do_p_fn_rename_w_timestamp(lo_p_fn_flashcard, p_QA):
    # >lo_p_fn_flashcard< == a list of paths and >p_QA< a directory path.
    # It renames every element >p_fn_flashcard< of >lo_p_fn_flashcard< by adding to the tail of the filename
    # a string >.YYYY-MM-DD< which is the actual date and keep the extension, which must be >.md<.
    # If a file with this name already exists add >.YYYY-MM-DD_mm< to it, where 'mm' are minutes.
    tz = zoneinfo.ZoneInfo("Europe/Berlin")
    date_str = datetime.now(tz).strftime("%Y-%m-%d")
    for p_fn in lo_p_fn_flashcard:
        dir_path, fn = os.path.split(p_fn)
        name, ext = os.path.splitext(fn)
        if ext != '.md':
            continue
        new_fn = f"{name}.{date_str}{ext}"
        new_path = os.path.join(dir_path or p_QA, new_fn)
        counter = 0
        while os.path.exists(new_path):
            hrs  = datetime.now(tz).strftime("%H")
            mins = datetime.now(tz).strftime("%M")
            new_fn = f"{name}.{date_str}_{hrs}_{mins}{ext}"
            new_path = os.path.join(dir_path or p_QA, new_fn)
            counter += 1
            if counter > 60:
                break
        os.rename(p_fn, new_path)


def b_filter_backup_flashcard_file(p_fn, s_extension):
    # Check if the tail of the filename is a string >.YYYY-MM-DD< or a string  >.YYYY-MM-DD_mm< and
    # if the filename ends with the extension >s_extension< and returns True if so.
    base, ext = os.path.splitext(p_fn)
    if ext != s_extension:
        return False
    return rgx_flashcard_backup.search(base) is not None


def get_duplicates_by_key(lo_do_QA, key):
    # lo_do_QA: list of dicts
    # key:   the key you want to check for duplicates, e.g. "QA_ID"
    values = [d[key] for d in lo_do_QA]
    counts = Counter(values)
    return [d for d in lo_do_QA if counts[d[key]] > 1]

def sort_and_clear_lo_do_QA(lo_do_QA_flashcard):
    # CLears duplicates and sorts by x["QA_ID"]
    if not lo_do_QA_flashcard:
        return None
    lo_do_QA_flashcard.sort(key=lambda x: x["QA_ID"])
    duplicates = {}
    for i, do in enumerate(lo_do_QA_flashcard):
        qa_id = do["QA_ID"]
        if qa_id in duplicates:
            duplicates[qa_id].append(i)
        else:
            duplicates[qa_id] = [i]
    for qa_id, indices in duplicates.items():
        if len(indices) > 1:
            print('sort_and_clear_lo_do_QA(): ')
            print(f"Duplicate QA_ID '{qa_id}' at indices: {indices}")
            lo_do_QA_flashcard = get_duplicates_by_key(lo_do_QA_flashcard, "QA_ID")
            lo_do_QA_flashcard.sort(key=lambda x: x["QA_ID"])

            pprint (lo_do_QA_flashcard)
            exit()
            break
    return lo_do_QA_flashcard


def write_flashcard_file(lo_do_QA_merged, p_QA=r'\obsidian_rh_GoogleDrive\99_QA', fn='flashcards.md'):
    # Check in directory >p_QA< if there is a file >fn<.
    # reads the file by calling >get_lo_do_QA_flashcard(lo_p_fn_flashcard)< which returns a list of dicts >lo_do_QA_flashcard<.

    # When finished the program sorts the list of dictionaries >lo_do_QA_flashcard< using an element of >do_QA_flashcard< with the key >"QA_ID"<.
    # If >do_QA_flashcard< was b_modified_lo_do_QA_flashcard use >do_p_fn_rename_w_timestamp(lo_p_fn_flashcard, p_QA)< to rename the existing version.
    # Write every element in >lo_do_QA_flashcard< into the new file separating each element from the ather by adding an empty line.
    # The dictionary has the elements: 'path', 'fn', "QA_deck", "QA", "QA_Q", "QA_A", "QA_TimeStamp", "QA_zotero_hash", "QA_d8_hash", "QA_ID".
    # Use the keys:  "QA_deck", "QA_Q", "QA_A", "QA_ID", "QA_TimeStamp"  in this order.

    if not lo_do_QA_merged:
        return None

    # Compose the full path >p_fn< of the file,
    p_fn = os.path.join(p_QA, fn).replace('\\', '/')
    # Initialize flashcard file if it does not exist:
    if not os.path.exists(p_fn):
        with open(p_fn, 'w') as f:
            f.write("#flashcards\n")

    # Read the existing flashcard file
    lo_p_fn_flashcard = [p_fn]
    lo_do_QA_flashcard = get_lo_do_QA_flashcard(lo_p_fn_flashcard)

    # The function sorts the list >lo_do_QA_flashcard< of dictionaries >do_QA_flashcard< by the element of >do_QA_flashcard< with the key >"QA_ID"<.
    # If there are two or more dictionaries >do_QA_flashcard< with identical value in key >"QA_ID"< then print these values and exit.
    lo_do_QA_flashcard = sort_and_clear_lo_do_QA(lo_do_QA_flashcard)
    # The function sorts the list >lo_do_QA_merged< of dictionaries >do_QA_flashcard< by the element of >do_QA_flashcard< with the key >"QA_ID"<.
    # If there are two or more dictionaries >do_QA_flashcard< with identical value in key >"QA_ID"< then print these values and exit.
    lo_do_QA_merged    = sort_and_clear_lo_do_QA(lo_do_QA_merged)

    # For every element >do_QA_flashcard_updated< in >lo_do_QA_merged<, which is a list of dictionaries,
    # the program checks if it is present in >lo_do_QA_flashcard<. If not it appends this element to >lo_do_QA_flashcard<.
    b_modified_lo_do_QA_flashcard = False
    # There are QA
    for do_QA_merged in lo_do_QA_merged:
        if lo_do_QA_flashcard:
            if not any(d["QA_ID"] == do_QA_merged["QA_ID"] for d in lo_do_QA_flashcard):
                lo_do_QA_flashcard.append(do_QA_merged)
                b_modified_lo_do_QA_flashcard = True
        else:
            lo_do_QA_flashcard = []
            lo_do_QA_flashcard.append(do_QA_merged)
            b_modified_lo_do_QA_flashcard = True

    if b_modified_lo_do_QA_flashcard:
        do_p_fn_rename_w_timestamp(lo_p_fn_flashcard, p_QA)

    if lo_do_QA_flashcard:
        lo_do_QA_flashcard.sort(key=lambda x: x["QA_ID"])
        with open(p_fn, 'w', encoding='utf-8') as f:
            for do in lo_do_QA_flashcard:
                lines = [
                    str(do.get("QA_deck", "")),
                    str(do.get("QA_Q", "")),
                    '?',
                    str(do.get("QA_A", "")),
                    '.',
                    str(do.get("fn", "")),
                    str(do.get("QA_ID", "")),
                    str(do.get("QA_TimeStamp", ""))
                ]
                f.write('\n'.join(lines) + '\n\n')

def main():
    ini_path = 'tac.ini'
    p_root, ext, p_QA, QA_tag = load_config(ini_path)

    # all obsidian notes in file system:
    all_notes_md   = find_files_with_extension(p_root, ext)

    # get >lo_do_QA_entry< == list of all QA in *.md but not in QA-files (flashcard|anki| ...)
    lo_do_QA_entry = []
    lo_do_QA_entry.extend(get_lo_qa_entry(all_notes_md))

    # pprint(lo_do_QA_entry)
    # print("Total QA entries:", len(lo_do_QA_entry))

    # get FILE NAMES: >lo_p_fn_flashcard< == FILES that contain Q&As in flashcard format (== Spaced Repetition)
    lo_p_fn_flashcard = get_lo_p_fn_flashcard(QA_tag, p_QA)

    # get >lo_do_QA_flashcard< == list of dict of all Q&A from flashcard FILES
    lo_do_QA_flashcard = []
    lo_do_QA_flashcard.extend(get_lo_do_QA_flashcard(lo_p_fn_flashcard))

    # pprint(lo_do_QA_flashcard)
    # print("Total QA entries:", len(lo_do_QA_flashcard))

    lo_do_QA_merged = get_merge_lo_do_QA(lo_do_QA_entry, lo_do_QA_flashcard)
    pprint(lo_do_QA_merged)
    print("Total QA entries:", len(lo_do_QA_entry))
    print("Total QA_flashcard entries:", len(lo_do_QA_flashcard))
    # print("Total QA_flashcard entries updated:", len(lo_do_QA_merged))
    # print("Total QA entries:", len(lo_do_QA_flashcard))
    # pprint(lo_do_QA_merged)

    # write_flashcard_file(lo_do_QA_merged, p_QA=r'\obsidian_rh_GoogleDrive\99_QA', fn='flashcards.md')
    write_flashcard_file(lo_do_QA_merged, p_QA = p_QA, fn='flashcards.md')

if __name__ == "__main__":
    main()
