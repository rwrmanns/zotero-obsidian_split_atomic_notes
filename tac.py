# @formatter:off
'''
tac == _T_ransfer (to)  _A_nki _C_ards  ...
... but connections to anki did not work, so the Spaced Repetition version was programmed.

vs 1.xx:  _without_ connecting to anki, but using Spaced Repetition obsidian plugin.

This script serves to extract QA text-blocks in obsidian files to be used in Spaced Repetition flashcards
(aka SR-plugin) (or to be transfered to anki (not yet realized)).

Script scans obsidian notes for QA-text blocks and transfers them into specific obsidian flashcard notes,
that can be used to generate flashcards by obsidian plugin >Spaced Repetition< or by anki (to realize).
The SR-plugin adds certain informations to the entries, to realize the repetition process.

The paths pf the obsidian notes are configured in >tac.ini<

QA-text blocks begin with a specific tag (QA-tag) followed by a Question - Answer section.

Script checks if QA-text blocks already transfered, if not it changes the tag to the SR-format and adds the block.
Every QA-text block gets a individual hash value >QA_ID<, specific of QA-Text, file origin and QA-tag.
The filename of obsidian note is added.

Configuration of SR-plugin:
- let the default flashcard tag >#flashcards< unchanged.

github repository:
    https://github.com/rwrmanns/zotero-obsidian_split_atomic_notes


do_QA = {
    'path'           : file_path,        # f path
    "QA_zotero_hash" : QA_zotero_hash,   # hash of note (from frontmatter - but where does it come from ??)

    "QA_tag"         : do_QA["QA_tag"],  # tag of QA
    "QA"             : s_QA,             # complete string of QA
    "QA_Q"           : QA_Q,             # Question
    "QA_A"           : QA_A,             # Answer
    'fn_QA'          : fn_QA,            # filename: origin of QA-block
    "QA_ID"          : QA_ID             # specific ID of QA + tag.
                                         # if >QA_d8_hash< != third part of  >QA_ID<   => >QA< ond/or tag has changed.
    "QA_d8_hash"     : QA_d8_hash,       # hash of (QA-Text + QA_tag)
    "SR_TimeStamp"   : SR_TimeStamp,     # timestamp of Spaced Repetition obsidian plugin
}

'''


import configparser
import deepdiff
import difflib
import frontmatter
import hashlib
import io
import os
import random
import re
import sys
import zoneinfo

from collections import Counter
from datetime import date
from datetime import datetime
from os.path import basename
from pprint import pprint
from re import split


import json

flashcard_sys = 'anki'
flashcard_sys = 'spaced_repetition'

p_root        = ''
lo_subdir     = []
ext           = ''

dir_QA_cards  = ''  # dir containing QA file(s): Spaced Repetition or anki.
fn_QA_SR      = ''  # fn_QA of Spaced_Repetition specific flashcards File  (from >tac.ini<)
fn_QA_anki    = ''  # fn_QA of Anki              specific flashcards File  (from >tac.ini<)

QA_tag        = ''
SR_tag        = ''

cnt_new_QA    = 0

fn_prefix     = '_NEW_'

QA_separator  = '...'

rgx_html_comment = re.compile(r'<!--.*?-->', re.DOTALL)

rgx_QA_exclude       = None
rgx_QA_DECK          = None
rgx_d8_hash          = None
rgx_QA_startword     = None
rgx_QA_block         = None
rgx_QA_split         = None
rgx_QA_ID            = None          # QA_ID: unique identifier of QA + tag
rgx_QA_SR_hash       = None          #
rgx_html_comment     = None          # Regex that matches HTML comments (including multiline) == SR - Time Stamp
rgx_flashcard_backup = None
rgx_norm_QA_deck     = None


def get_rgx_QA_block():
    # gemini

    # 1. Define the base keywords list
    # Note: Added '?' to #flashcards to handle plural/singular mismatch between prompt list and input text
    keywords = [r'#flashcards?', r'#QA']

    # Join keywords for regex OR logic: (#flashcards?|#QA)
    keywords_pattern = '|'.join(keywords)

    # 2. Define the Regex Parts
    # Start Tag: Keywords + optional ext (starting with _ or / per your examples)
    # We use (?:...) for non-capturing groups to keep the result clean
    rgx_start = fr"(?:{keywords_pattern})(?:[_\/][\w\/]{{0,30}})?"

    # Stop Tag / Separator: The literal ___ or --- or the start of a new tag
    # We use a Lookahead (?=...) so we check for the stop tag but do not include it in the match
    rgx_stop_lookahead = fr"(?=^{rgx_start}|^(?:---|___)\s*$|\Z)"

    # 3. Compile the Full Regex
    # Pattern: (Start_Tag)(Content)(Stop_Lookahead)
    # Flags:
    #   re.MULTILINE (m): ^ matches start of lines
    #   re.DOTALL (s): . matches newlines (so we capture multi-line content)
    rgx_QA_block = re.compile(
        fr"(?P<block>^{rgx_start}.*?){rgx_stop_lookahead}",
        re.MULTILINE | re.DOTALL
    )
    return rgx_QA_block, rgx_start


def load_config(ini_path):
    global rgx_QA_exclude
    global rgx_QA_DECK
    global rgx_d8_hash
    global rgx_QA_startword
    global rgx_QA_block
    global rgx_QA_split
    global rgx_QA_ID
    global rgx_QA_SR_hash
    global rgx_html_comment      # SR_TimeStamp

    global rgx_flashcard_backup
    global rgx_norm_QA_deck

    global p_root
    global lo_subdir    # subdirs with *.md files with QA-blocks

    global dir_QA_cards
    global fn_QA_SR
    global fn_QA_anki

    global ext

    global QA_tag
    global SR_tag

    config = configparser.ConfigParser()
    config.read(ini_path)


    p_root           = config['DEFAULT']['p_root']
    subdirs_raw      = config['DEFAULT']['lo_subdir']
    lo_subdir        = [subdir.strip() for subdir in subdirs_raw.split(",")]

    dir_QA_cards     = config['DEFAULT']['dir_QA_cards']
    fn_QA_SR         = config['DEFAULT']['fn_QA_SR']
    fn_QA_anki       = config['DEFAULT']['fn_QA_anki']

    ext              = config['DEFAULT']['ext']

    QA_tag           = config['DEFAULT']['QA_tag']
    SR_tag           = config['DEFAULT']['SR_tag']

    rgx_QA_exclude   = re.compile(config['DEFAULT']['rgx_QA_exclude'], re.MULTILINE | re.DOTALL)
    rgx_QA_DECK      = re.compile(config['DEFAULT']['rgx_QA_DECK'], re.MULTILINE | re.DOTALL)
    # rgx_d8_hash      = re.compile(config['DEFAULT']['rgx_d8_hash'], re.MULTILINE | re.DOTALL)
    rgx_QA_ID        = re.compile(config['DEFAULT']['str_QA_ID'])
    rgx_html_comment = re.compile(r'<!--.*?-->', re.DOTALL)
    rgx_QA_SR_hash   = re.compile(r"([A-Z0-9]{8})(?:_(\d{3}))?(?:_(\d{8}))?")


    #########  rgx_QA_block  ###########
    QA_lo_start_tag  = ['#flashcards', '#QA']
    lo_QA_startword  = [re.escape(sw) for sw in QA_lo_start_tag]
    s_startword_tail = r"[A-Za-z0-9_/\-\\]{0,25}"
    rgx_QA_startword = r"(?:%s)%s" % ("|".join(lo_QA_startword), s_startword_tail)

    # QA_lo_start_tag = ['#flashcards', '#QA']
    # lo_QA_startword = [re.escape(sw) for sw in QA_lo_start_tag]
    # s_startword_tail = r"_[A-Za-z0-9_/\-\\]{0,25}"
    #
    # rgx_QA_startword = rf'^({"|".join(lo_QA_startword)}){s_startword_tail}?$'


    # Escape each tag so '#' and other characters become literal.
    rgx_QA_lo_start_tag = "|".join(re.escape(tag) + r"_[A-Za-z0-9._-]+" for tag in QA_lo_start_tag)  # tag + file-safe chars

    # Compile begin-regex (still matches only at the beginning of a line)
    rgx_QA_block_begin = re.compile(rf"^(?:{rgx_QA_lo_start_tag})", re.MULTILINE)

    # Compile begin-regex (still matches only at the beginning of a line)
    # rgx_QA_block_begin = re.compile(rf"^(?:{rgx_QA_startword})", re.MULTILINE)

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

    rgx_QA_block, rgx_norm_QA_deck = get_rgx_QA_block()

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
        \.                        # literal dot
        \d{4}-\d{2}-\d{2}         # YYYY-MM-DD
        (?:_\d{2}-\d{2}-\d{2})?   # optional _hh-mm-ss (two digits)
        $                         # end of string
        """,
        re.VERBOSE,
    )

    # Flashcard tags: or '#flashcards' or some user defined tag.
    # We use: '#flashcards' or 'QA_*'. Something like '#QA_myQuestion' will
    # be splitted into: '#QA/myQuestion'
    # rgx_norm_QA_deck = re.compile(r"^(#QA)_([A-Za-z0-9/_-]+)$", flags=re.IGNORECASE)

    # rgx_d8_hash matches an 8 digit hash preceded by '_'
    rgx_d8_hash = r"_\d{8}"

    return p_root, ext, dir_QA_cards, SR_tag


def remove_color_tags(text):
    # 1. Pattern for legacy <font color="..."> tags
    # Matches <font [anything] > [content] </font>
    # We use re.IGNORECASE to handle <FONT> or <font>
    # We use re.DOTALL to handle tags spanning multiple lines
    font_tag_pattern = r'<font\b[^>]*>(.*?)</font>'

    # 2. Pattern for <span style="...color:..."> tags
    # Matches <span [anything] style="[anything]color:[anything]" [anything] > [content] </span>
    span_color_pattern = r'<span\b[^>]*\bstyle=[^>]*color:[^>]*>(.*?)</span>'

    # Remove <font> tags first
    # \1 refers to the first capture group (the text inside the tags)
    cleaned_text = re.sub(font_tag_pattern, r'\1', text, flags=re.IGNORECASE | re.DOTALL)

    # Remove <span> tags with color styles
    cleaned_text = re.sub(span_color_pattern, r'\1', cleaned_text, flags=re.IGNORECASE | re.DOTALL)

    return cleaned_text

# # --- Test ---
#
# markdown_input = """
# # Header
# This is normal text.
# This is <font color="red">red text using the font tag</font>.
# This is <span style="color: blue;">blue text using inline css</span>.
# This is <font color='#00FF00'>hex color text</font>.
# Mixed <span style="font-weight:bold; color:green">bold and green</span> text.
# """
#
# result = remove_color_tags(markdown_input)
#
# print("-------- Original --------")
# print(markdown_input)
# print("\n-------- Cleaned --------")
# print(result)

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

def get_lo_QA_entry_tag_block(text):
    # do_QA == block of text ...
    # ... beginning with tag indicating tag of one or more following QAs.

    # lo_QA_tag_block = []
    # matches = [block.group() for block in rgx_QA_block.finditer(text)]
    # if not matches:
    #     return []
    #
    # for idx, block_text in enumerate(matches):
    #

    lo_QA_tag_block = []
    # matches = [block.group() for block in rgx_QA_block.finditer(text)]
    lo_match = [block for block in rgx_QA_block.finditer(text)]
    if not lo_match:
        return []

    # for idx, block_text in enumerate(matches):
    for match in lo_match:
        block_text       = text[match.start():match.end()]
        match_start      = match.start()

        # for example: #ToDo_QA
        if rgx_QA_exclude.search(block_text):
            continue

        lines = block_text.splitlines()

        tag_line  = lines[0]
        qa_lines  = lines[1:]

        tag_line  = "\n".join(ln for ln in [tag_line] if get_cleaned_line(ln))
        qa_clean  = "\n".join(ln for ln in qa_lines   if get_cleaned_line(ln))

        # list of decks
        lo_QA_tag = re.findall(rgx_QA_startword, tag_line)

        # get link to previous heading in the note
        QA_heading_link = get_previous_heading(text, match_start)

        lo_QA_tag_block.append({
            "tag_line"        : tag_line,
            "QA"              : qa_clean,
            "QA_heading_link" : QA_heading_link,  # Link to previous heading of QA
            "lo_QA_tag"       : lo_QA_tag
        })

    return lo_QA_tag_block


def get_lo_d_QA_entry(do_QA):
    # When tagline contains more than one tag:
    # transform >do_QA< into cartesian product (lo of dict):
    #    one tag of first line
    #    X
    #    following elements.

    # Get (list of) tag, QA text in dict:
    lo_QA_tag = do_QA["lo_QA_tag"]
    QA_text   = do_QA["QA"]

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

    lo_do_QA_entry = []
    for QA_tag in lo_QA_tag:
        for s_QA in lo_s_QA:
            lo_do_QA_entry.append({
                "QA_tag"          : QA_tag,
                "s_QA"            : s_QA,                      # text block containing the rest of the text.
                "QA_heading_link" : do_QA["QA_heading_link"],  # Link to previous heading of QA
            })
    return lo_do_QA_entry


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

def b_d8_hash_ok_do_QA(do_QA):

    s_QA_tag      = do_QA["QA_tag"]
    s_QA          = do_QA["QA"]
    s_QA_d8_hash  = do_QA["QA_d8_hash"]

    s_tag_and_QA  = do_QA["QA_tag"] + ' - ' + s_QA
    QA_d8_hash    = get_d8_hash(s_tag_and_QA)
    QA_ID         = get_QA_ID(s_QA)

    return (QA_d8_hash == s_QA_d8_hash)


def get_previous_heading(textblock, pos):
    """
    Searches backwards from an absolute character position in the textblock
    to find the previous higher-level heading or the Note_Title.
    """
    # 1. Split text into lines but keep track of their original positions
    lines = textblock.splitlines(keepends=True)

    current_offset = 0
    target_line_idx = -1

    # 2. Identify which line index the absolute 'pos' belongs to
    for i, line in enumerate(lines):
        line_length = len(line)
        if current_offset <= pos < current_offset + line_length:
            target_line_idx = i
            break
        current_offset += line_length

    # Handle case where pos is at the very end of the file
    if target_line_idx == -1 and pos >= current_offset:
        target_line_idx = len(lines) - 1

    def get_info(idx):
        if idx < 0: return None, None
        line = lines[idx].strip()
        if line.startswith('#'):
            level = len(line) - len(line.lstrip('#'))
            # Validate standard Markdown heading (hashes followed by space)
            if line.startswith('#' * level + ' '):
                return level, line.lstrip('#').strip()
        return None, None

    # 3. Establish the baseline heading level above the current position
    baseline_level = 999
    for i in range(target_line_idx - 1, -1, -1):
        level, content = get_info(i)
        if level:
            baseline_level = level
            break

    # 4. Search for the next higher level heading (fewer # symbols)
    for i in range(target_line_idx - 1, -1, -1):
        level, content = get_info(i)

        # If we find a heading with a smaller level (e.g., H1 is higher than H2)
        if level and level < baseline_level:
            return content

        # If we hit the first line and it's not a heading, it's the Note_Title
        if i == 0 and level is None:
            return lines[0].strip()

    return None

def get_normalized_QA_tag(s_QA_tag):
    # If >s_QA_tag< begins with: '#flashcards'
    # if s_QA_tag.startswith("#flashcards"): return s_QA_tag

    s_QA_tag = re.sub(r"_+", "_", s_QA_tag)
    # s_QA_tag = re.sub(r"_", "/", s_QA_tag)
    return f"{s_QA_tag}"


def get_normalized_lo_do_QA(lo_do_QA, file_path, fn_QA, QA_zotero_hash):
    # purge some html comments and hashes
    # normalize Spaced Repetition tag

    lo_do_QA_normalized = []
    for do_QA in lo_do_QA:
        s_QA = do_QA["s_QA"]

        # Extract SR_TimeStamp ( is in HTML comment )
        m_comment    = rgx_html_comment.search(s_QA)
        SR_TimeStamp = m_comment.group(0) if m_comment else None

        # Purge HTML comments from s_QA
        s_QA       = rgx_html_comment.sub("", s_QA)
        s_QA       = s_QA.strip()

        # get Q & A
        QA_Q, QA_A = get_QA_Q_and_A(s_QA)

        # normalize Spaced Repetition tag:
        qa_tag     = get_normalized_QA_tag(do_QA["QA_tag"])
        do_QA["QA_tag"] = qa_tag

        # do_QA["QA_tag"] = get_normalized_QA_tag(do_QA["QA_tag"])
        # If there is no "QA_ID" at the end of QA_A
        s_deck_and_QA = do_QA["QA_tag"] + ' - ' + s_QA
        QA_d8_hash = get_d8_hash(s_deck_and_QA)
        QA_ID = get_QA_ID(s_QA)

        m_QA_ID = rgx_QA_ID.search(s_QA)
        QA_ID   = m_QA_ID.group(0) if m_QA_ID else None

        if not QA_ID:
            # Compute new deterministic hash == ID from original s_QA combining QA-text and tag.
            QA_ID = '(' + 'QA_ID_' + QA_zotero_hash + '_' + QA_d8_hash + ')'  # specific ID of QA + tag.

        # Build normalized dict
        do_QA = {
            'path'           : file_path,        # f path
            "QA_zotero_hash" : QA_zotero_hash,   # hash of note (from frontmatter - but where does it come from ??)

            "QA_tag"         : do_QA["QA_tag"],  # tag of QA
            "QA"             : s_QA,             # complete string of QA
            "QA_Q"           : QA_Q,             # Question
            "QA_A"           : QA_A,             # Answer

            #'QA_link'        : link_QA,          # link to note
            'fn_QA'          : fn_QA,            # filename: origin of QA-block
            "QA_ID"          : QA_ID,            # specific ID of QA + tag.
            "QA_d8_hash"     : QA_d8_hash,       # hash of (QA-Text + QA_tag)
                                                 # ?? if >QA_d8_hash< != third part of  >QA_ID<   => >QA< ond/or tag has changed.
            "SR_TimeStamp"   : SR_TimeStamp,     # timestamp of Spaced Repetition obsidian plugin
        }

        if b_d8_hash_ok_do_QA(do_QA):
            lo_do_QA_normalized.append(do_QA)

    return lo_do_QA_normalized

def get_colorized_string(s_input: str) -> str:
    s_output = "<font color=#494429>" + s_input + "</font>"
    return s_output


def get_normalized_do_QA_SR(do_QA_SR_raw, file_path, QA_zotero_hash):
    # normalize entries (in >lo_do_QA_SR_raw<) ==
    #   add hash if necessary
    #   add color to fn_QA, QA_ID, hash

    # do_QA_SR_normalized = []
    # for do_QA_SR_raw in lo_do_QA_SR_raw:

    # adjust >QA_d8_hash< if necessary
    QA_d8_hash = do_QA_SR_raw["QA_d8_hash"]
    if (QA_d8_hash == '') or (QA_d8_hash == 'None'):
        QA_d8_hash = get_d8_hash(do_QA_SR_raw["QA"] + do_QA_SR_raw["QA_tag"]) # QA-text + flashcard-tag

    # colorize strings: fn_QA
    fn_QA = do_QA_SR_raw["fn_QA"]
    # fn_QA = get_colorized_string(fn_QA)

    # colorize strings: QA_ID
    QA_ID = do_QA_SR_raw["QA_ID"]
    # QA_ID = get_colorized_string(QA_ID)

    # colorize strings: QA_d8_hash
    # QA_d8_hash = get_colorized_string(QA_d8_hash)

    # 'path'           : file_path,        # f path
    # "QA_zotero_hash" : QA_zotero_hash,   # hash of note (from frontmatter - but where does it come from ??)
    #
    # "QA_tag"         : do_QA["QA_tag"],  # tag of QA
    # "QA"             : s_QA,             # complete string of QA
    # "QA_Q"           : QA_Q,             # Question
    # "QA_A"           : QA_A,             # Answer
    # 'fn_QA'          : fn_QA,            # filename: origin of QA-block
    # "QA_ID"          : QA_ID             # specific ID of QA + tag.
    # # if >QA_d8_hash< != third part of  >QA_ID<   => >QA< ond/or tag has changed.
    # "QA_d8_hash"     : QA_d8_hash,       # hash of (QA-Text + QA_tag)
    # "SR_TimeStamp"   : SR_TimeStamp,     # timestamp of Spaced Repetition obsidian plugin


    do_QA_SR_normalized = {
        'path'           : file_path,                     # f path
        "QA_zotero_hash" : QA_zotero_hash,                # hash of note (from frontmatter - but where does it come from ??)

        "QA_tag"         : do_QA_SR_raw["QA_tag"],        # tag of QA

        "QA"             : do_QA_SR_raw["QA"],            # complete string of QA
        # "QA_Q"         : do_QA_SR_raw[],                # Question
        # "QA_A"         : do_QA_SR_raw[],                # Answer

        'fn_QA'          : fn_QA,                         # filename: origin of QA-block
        "QA_ID"          : QA_ID,                         # specific ID of QA + tag.
        "QA_d8_hash"     : QA_d8_hash,                    # hash of (QA-Text + QA_tag)
                                                          # ?? if >QA_d8_hash< != third part of  >QA_ID<   => >QA< ond/or tag has changed.
        "SR_TimeStamp"   : do_QA_SR_raw["SR_TimeStamp"],  # timestamp of Spaced Repetition obsidian plugin
    }
    # do_QA_SR_normalized.append(do_QA_SR_normalized)

    return do_QA_SR_normalized



def get_lo_fn_path_with_extension(root, lo_subdir, ext):

    def add_path(ext, lo_fn_pth, root_path):
        # print(f'>add_path():< {root_path = } ')
        # 'C:\\Users\\rh\\Meine Ablage\\obsidian_rh_GoogleDrive\\02_Notes_zotero_Annotations_anki\\bleasePaternalismus2016__Annotations__OK\\01_Notes_rh'
        # 'C:\\Users\\rh\\Meine Ablage\\obsidian_rh_GoogleDrive\\02_Notes_zotero_Annotations_anki\\bleasePaternalismus2016__Annotations__OK\\01_Notes_rh'
        list_dir = os.listdir(os.path.normpath(root_path))
        # pprint(list_dir)
        for current_dir, _, filenames in os.walk(root_path):
            for fname in filenames:
                if fname.endswith(ext):
                    path_fn = os.path.normpath(os.path.join(current_dir, fname))
                    lo_fn_pth.append(path_fn)
                    # print(f'{path_fn=}')

    lo_fn_pth = []
    print(f'>get_lo_fn_path_with_extension()<: {root = }')
    if lo_subdir:
        for subdir in lo_subdir:
            root_path = os.path.join(root, subdir)
            # print(f' {subdir =    } \n {root_path = }')
            print(f'  {subdir = }')
            add_path(ext, lo_fn_pth, root_path)
    else:
        add_path(ext, lo_fn_pth, root)

    print()
    return lo_fn_pth


def get_l_s_QA_deck(content, fixed_QA_prefix):
    # rgx_QA_DECK matches the (flashcard-) tags for Spaced Repetition
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
    elif flashcard_sys == 'spaced_repetition':
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
    if flashcard_sys == 'spaced_repetition':

        iter_QA_match  = rgx_QA_block.finditer(content)
        for QA_match in iter_QA_match:
            if QA_match:
                s_lo_QA_deck = QA_match.group('rgx_lo_QA_deck')
                QA_Question  = QA_match.group('QA_Question')
                QA_type      = QA_match.group('QA_type')
                QA_Answer    = QA_match.group('QA_Answer')
                lo_QA_deck   = s_lo_QA_deck.split(' ')
            else:
                return None

        l_qa_match = rgx_QA_block.findall(content)
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


def get_lo_QA_file(file_paths):
    # return list of lo_fn_note that contain QA - text blocks.
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
        QA_matches =  rgx_QA_block.finditer(content)
        if not QA_matches:
            continue

        d_QA_file = dict()
        d_QA_file['fn_QA']   = fn
        d_QA_file['path']    = file_path
        d_QA_file['post']    = post
        d_QA_file['content'] = content
        lo_do_QA_files.append(d_QA_file)
    return lo_do_QA_files


def get_lo_QA_entry(lo_fn_note):
    # return list of all QA-entries of every obsidian note that is in >lo_fn_note<:

    # >lo_do_QA_note< list of all files with QA section.
    lo_do_QA_note      = get_lo_QA_file(lo_fn_note)

    lo_do_QA_entry     = []
    for do_QA_note in lo_do_QA_note:
        # QA == Question-Answer text .
        file_path      = do_QA_note['path']
        fn_QA          = do_QA_note['fn_QA']
        content        = do_QA_note['content']
        post           = do_QA_note['post']

        metadata       = post.metadata
        QA_zotero_hash = get_QA_zotero_hash_from_frontmatter(file_path, metadata, post, rgx_QA_SR_hash)

        # do_QA == block of text beginning with tag indicating tag of one or more QAs.
        lo_QA_entry_tag_block = get_lo_QA_entry_tag_block(content)

        # >lo_do_QA_entry_org< == raw QA text block as is (with Timestamp, Anki-, obsidian- ID or similar ...)
        lo_do_QA_entry_org = []
        # If a QA-textblock has multiple tags:
        #   transform multiple QA-textblock in multiple dicts of QA: "QA_tag": ..., "s_QA": ...
        for QA_entry_tag_block in lo_QA_entry_tag_block:
            lo_do_QA_entry_org.extend(get_lo_d_QA_entry(QA_entry_tag_block))

        # normalize every d_QA and add hash of Text of QA
        # Normalize and clean QA from Timestamp of Spaced Repetition and ID of tac.py and ...
        # ... add: link_to_origin, file_path, fn_QA_SR, QA_zotero_hash
        lo_do_QA_entry.extend(get_normalized_lo_do_QA(lo_do_QA_entry_org, file_path, fn_QA, QA_zotero_hash))

    return lo_do_QA_entry


# def get_lo_do_QA_SR(lo_fn_SR):

def split_f_SR_into_lo_do_QA_SR(fn_SR) -> list:
    # Splits the text file >fn_SR< (SR flashcard file) into a list of >do_QA_SR< == dicts corresponding to QA entries. )
    lo_do_QA_SR_org = []

    # Initialize flashcard file if it does not exist:
    if not os.path.exists(fn_SR):
        with open(fn_SR, 'w') as f:
            # f.write("")
            print(f'>write_QA_SR_file()<: created: \n  {fn_SR}\n')
            return []

    with open(fn_SR, 'r', encoding='utf-8') as f:
        QA_file_text = f.read()

    lo_do_QA_SR  = []  # list QA_txts, that contain QA

    QA_file_text = remove_color_tags(QA_file_text)

    # Split s_text into blocks by lines starting with '#flashcards'
    lo_QA_txt = re.split(r'(?=^#flashcards[^\n]*)', QA_file_text, flags=re.MULTILINE)

    # QA_txt ==
    #   one or more flashcard tags (decks) on first line
    #   followed by one or more QA that may be on one or more lines.
    #   ending when next flashcard tags are detected.

    for QA_txt in lo_QA_txt:
        lines = QA_txt.strip().splitlines()
        # May be no text at all in >QA_txt<, only empty lines -> next QA_txt

        if not lines:
            continue

        # First line contains tags ('#flashcards') indicating individual decks
        tag_line = lines[0]
        # QA - lines:
        txt_lines = lines[1:]  # text lines up to the end of QA_txt.
        #     >txt_lines< contain Q&A ...
        #     followed by QA_separator (global, defined in tac.ini)
        #     followed by fn_QA of obsidian note of origin
        #     followed by QA_ID
        #     followed by hash
        # +/- followed by SR timestamp

        tag_line  = "\n".join(ln for ln in [tag_line] if get_cleaned_line(ln))

        # get all (flashcard-) tags - should be only one entry.
        lo_QA_tag = re.findall(rgx_QA_startword, tag_line)

        QA_lines  = []  # lines containing the QA-section.
        idx_separ = 0  # indicates last line of QA-section.
        for idx, line in enumerate(txt_lines):
            if line == QA_separator:
                idx_separ = idx
                break
            else:
                QA_lines.append(line)

        QA_lines = "\n".join(ln for ln in QA_lines if get_cleaned_line(ln))

        # rgx_html_comment.sub("", s_QA)

        fn_QA         = txt_lines[idx_separ + 1]
        QA_ID         = txt_lines[idx_separ + 2]
        QA_d8_hash    = txt_lines[idx_separ + 3]

        SR_TimeStamp = None
        try:
            if txt_lines[idx_separ + 4]:
                m_comment     = rgx_html_comment.search(txt_lines[idx_separ + 4])
                SR_TimeStamp  = m_comment.group(0) if m_comment else None
            else:
                SR_TimeStamp = None  # Not yet used/inserted by Spaced Repetition
        except:
            SR_TimeStamp = None


        do_QA_SR_org = {
            "tag_line"    : tag_line,       # string with +- multiple tags
            "lo_QA_tag"   : lo_QA_tag,      # list ! of tags
            "QA_tag"      : lo_QA_tag[0],   # first tag
            "QA"          : QA_lines,
            "fn_QA"       : fn_QA,
            "QA_ID"       : QA_ID,
            "QA_d8_hash"  : QA_d8_hash,     # may not be present
            "SR_TimeStamp": SR_TimeStamp,   # may not be present
        }

        # Normalize do_QA_SR: adjust value of >QA_d8_hash<, colorize text :
        #   QA_zotero_hash='flashcar' ... because there is no zotero hash, when origin is not a file imported from zotero .
        QA_zotero_hash='not_zotr'
        # if lo_do_QA_SR_org:
        #     lo_do_QA_SR_normalized = get_normalized_do_QA_SR(lo_do_QA_SR_org, file_path=fn_SR, QA_zotero_hash)
        #     lo_do_QA_SR.extend(lo_do_QA_SR_normalized)

        # for do_QA_SR_org in lo_do_QA_SR_org:
        do_QA_SR_normalized = get_normalized_do_QA_SR(do_QA_SR_org, file_path=fn_SR, QA_zotero_hash=QA_zotero_hash)
        lo_do_QA_SR.append(do_QA_SR_normalized)

    return lo_do_QA_SR

def get_lo_do_QA_SR(lo_fn_SR) -> list:
    # get all entries >do_QA_SR< in QA_SR-file (file with SR flashcards) == QAs to be used by SR.

    # get FILE NAMES: >lo_fn_SR< == FILES that contain QA-entries in _Spaced Repetition_ format.
    # Only this/these files are used by the Spaced Repetition Plugin in Obsidian to define flashcards.

    lo_do_QA_SR = []  # file containing the result.

    # With every QA_SR-file (file with SR flashcards):
    # 2025-12-30: nota:
    #   only one element in >lo_fn_SR<;
    #   multiple QA_SR-file not yet implemented.
    for fn_SR in lo_fn_SR:
        lo_do_QA_SR = split_f_SR_into_lo_do_QA_SR(fn_SR)
        return lo_do_QA_SR
    return lo_do_QA_SR


def get_lo_fn_SR():
    lo_fn_SR = [os.path.join(dir_QA_cards, fn_QA_SR)]
    return lo_fn_SR
    # As long as there is only one single QA_SR-file return this one as single element of list >lo_fn_SR<.
    # Otherwise:
    #   scan >dir_QA_cards< for *.md files.
    #   check if first line contains 'flashcards' as first element in first line. If so add file to list >lo_fn_SR<.


def get_lo_do_QA_merged(lo_do_qa_entry, lo_do_QA_SR):
    # Add to >lo_do_QA_SR< all items of >lo_do_qa_entry< that are not already present in >lo_do_QA_SR<.

    lo_do_QA_merged = []

    # Make a set of all QA_IDs in >lo_do_QA_SR<.
    # If QA_ID of element of >lo_do_qa_entry< is not present in >lo_do_QA_SR<
    #   then add it to >lo_do_QA_merged<.

    so_QA_SR_QA_ID  = set()  # set of all QA_IDs in >lo_do_QA_SR<
    # Add every QA_ID from >lo_do_QA_SR< (== QA_IDs present in SR-file) to set:
    for do_QA_SR in lo_do_QA_SR:
        so_QA_SR_QA_ID.add(do_QA_SR["QA_ID"])

    # >do_qa_entry["QA_ID"]< not in >so_QA_SR_QA_ID<   =>
    #   => new QA in obsidian note => append it to >lo_do_QA_merged<.
    for do_qa_entry in lo_do_qa_entry:
        if do_qa_entry["QA_ID"] not in so_QA_SR_QA_ID:
            print ('>>> ', do_qa_entry["fn_QA"])
            do_qa_entry['QA_tag'] = do_qa_entry['QA_tag'].replace(QA_tag, SR_tag)
            lo_do_QA_merged.append(do_qa_entry)

    # lo_do_QA_merged.extend(lo_do_QA_SR)
    return lo_do_QA_merged

def do_p_fn_SR_rename_w_timestamp(p_fn_SR, p_QA):
    # Rename >p_fn_SR< of >lo_fn_SR< by adding >.YYYY-MM-DD<  or >.YYYY-MM-DD_mm< .
    tz = zoneinfo.ZoneInfo("Europe/Berlin")
    date_str = datetime.now(tz).strftime("%Y-%m-%d_%H-%M-%S")
    dir_path, fn = os.path.split(p_fn_SR)
    name, ext = os.path.splitext(fn)
    new_fn = f"{name}.{date_str}{ext}"
    new_path = os.path.join(dir_path or p_QA, new_fn)
    os.rename(p_fn_SR, new_path)


def b_filter_backup_flashcard_file(p_fn, s_extension):
    # Check if the tail of the filename is a string >.YYYY-MM-DD< or a string  >.YYYY-MM-DD_mm< and
    # if the filename ends with the ext >s_extension< and returns True if so.
    base, ext = os.path.splitext(p_fn)
    if ext != s_extension:
        return False
    b_result = rgx_flashcard_backup.search(base) is not None
    return b_result


def get_duplicates_by_key(lo_do_QA, key):
    # lo_do_QA_SR_raw: list of dicts
    # key:      the key you want to check for duplicates, e.g. "QA_ID"
    values = [d[key] for d in lo_do_QA]
    counts = Counter(values)
    return [d for d in lo_do_QA if counts[d[key]] > 1]

def check_duplicates_lo_do_QA(lo_do_QA):
    # Check duplicates and sort by x["QA_ID"]
    if not lo_do_QA:
        return None

    duplicates = {}
    for i, do in enumerate(lo_do_QA):
        qa_id = do["QA_ID"]
        if qa_id in duplicates:
            duplicates[qa_id].append(i)
        else:
            duplicates[qa_id] = [i]

    # If duplicates found => Error and exit.
    for qa_id, indices in duplicates.items():
        if len(indices) > 1:
            print('>check_duplicates_lo_do_QA()<: ')
            print(f"Error: Duplicate QA_ID found.\n")
            break

    b_exit = False
    for qa_id, indices in duplicates.items():
        if len(indices) > 1:
            print('==========\n')
            b_exit = True
            # lo_do_QA_SR = get_duplicates_by_key(lo_do_QA_SR, "QA_ID")
            # lo_do_QA_SR.sort(key=lambda x: x["QA_ID"])

            QA_ID_old = ''
            for do_QA in lo_do_QA:
                if do_QA["QA_ID"] == qa_id:
                    print(f'{do_QA["QA_ID"]      = }')
                    print(f'{do_QA["fn_QA_SR"]   = }')
                    print(f'{do_QA["QA_d8_hash"] = }')
                    print('----------')

    if b_exit:
        print('==========\n', flush=True)
        sys.stdout.flush()
        exit('>check_duplicates_lo_do_QA()<: exit()')

    return lo_do_QA

def get_colorized_string(s_input):
    # <font color="#494429">(QA_ID_ABJFDY5I_04124ebe)</font>
    dark_color = "#494429"
    return f'<font color={dark_color}>' + s_input + '</font>'

def get_lo_do_QA_entry_new(lo_do_QA_entry, lo_do_QA_SR):
    # >lo_do_QA_entry< == entries in obsidian notes
    # >lo_do_QA_SR<    == entries in Spaced Repitition file
    # For every element >do_QA_entry< in >lo_do_QA_entry< (list of dict),
    #   check if it is present in >lo_do_QA_SR<. If not it appends this element to >lo_do_QA_SR<.

    global cnt_new_QA
    cnt_new_QA = 0

    lo_do_QA_entry_new = []
    if lo_do_QA_SR:
        for do_QA_entry in lo_do_QA_entry:
            if not any(do_QA_entry["QA_ID"]  == d["QA_ID"] for d in lo_do_QA_SR):
                lo_do_QA_entry_new.append(do_QA_entry)
                cnt_new_QA += 1
    else:
        lo_do_QA_entry_new.extend(lo_do_QA_entry)

    return lo_do_QA_entry_new

def write_QA_SR_file(lo_do_QA_merged):
    # Check in directory >dir_QA_cards< if there is a file >fn_QA_SR< == Spaced Repetition flashcard file
    # reads the file by calling >get_lo_do_QA_Spaced_Repetition(lo_fn_SR)< which returns a list of dicts >lo_do_QA_SR<.

    # The dictionary has the elements: 'path', 'fn_QA', "QA_tag", "QA", "QA_Q", "QA_A", "SR_TimeStamp", "QA_zotero_hash", "QA_d8_hash", "QA_ID".
    #
    # If >do_QA_flashcard< was modified (b_modified_lo_do_QA_SR == True):
    #    use >do_p_fn_SR_rename_w_timestamp(lo_fn_SR, dir_QA_cards)< to rename the existing version.
    #
    # Write every element in >lo_do_QA_SR< into the new file separating each element from the ather by adding an empty line.
    # Use the keys:  "QA_tag", "QA_Q", "QA_A", "QA_ID", "SR_TimeStamp"  in this order.

    # Compose the full path >p_fn_SR< of QA_SR-file (file with SR flashcards); create it if not existing.
    p_fn_SR = os.path.join(dir_QA_cards, fn_QA_SR).replace('\\', '/')
    # Initialize flashcard file if it does not exist:
    if not os.path.exists(p_fn_SR):
        with open(p_fn_SR, 'w') as f:
            f.write("")
            print(f'>write_QA_SR_file()<: created: \n  {p_fn_SR}\n')

    # Select new entries, i.e. entries not already

    # Read QA_entries in the existing Spaced Repetition flashcard file(s) >p_fn_SR<
    # n.b. Up today there is only one Spaced Repetition flashcard file.
    lo_do_QA_SR = get_lo_do_QA_SR(get_lo_fn_SR())


    # For every element >do_QA_merged< in >lo_do_QA_merged<, which is a list of dictionaries, the program
    #   checks if it is present in >lo_do_QA_SR<. If not it appends this element to >lo_do_QA_SR<.

    # If there are modified elements (ie QA was modified in obsidian note) -> backup Spaced Repetiton File
    b_modified_lo_do_QA_SR = False
    # There are QAs
    for do_QA_merged in lo_do_QA_merged:
        if lo_do_QA_SR:
            if not any(d["QA_ID"] == do_QA_merged["QA_ID"] for d in lo_do_QA_SR):
                lo_do_QA_SR.append(do_QA_merged)
                b_modified_lo_do_QA_SR = True
        else:
            lo_do_QA_SR = []
            lo_do_QA_SR.append(do_QA_merged)
            b_modified_lo_do_QA_SR = True

    if b_modified_lo_do_QA_SR:
        do_p_fn_SR_rename_w_timestamp(p_fn_SR, dir_QA_cards)


    if lo_do_QA_SR:
        # lo_do_QA_SR.sort(key=lambda x: x["QA_ID"])
        lo_do_QA_SR        = check_duplicates_lo_do_QA(lo_do_QA_SR)
        lo_do_QA_SR_sorted = sorted(lo_do_QA_SR, key=lambda x: (x["QA_tag"].lower()))

        with open(p_fn_SR, 'w', encoding='utf-8') as f:
            for do_QA_SR in lo_do_QA_SR_sorted:
                QA_ID = do_QA_SR.get("QA_ID", "")
                QA_Q  = do_QA_SR.get("QA_Q", "")
                QA_A  = do_QA_SR.get("QA_A", "")
                # print(QA_ID)
                lines = [
                    str(do_QA_SR.get("QA_tag", "")),
                    str(do_QA_SR.get("QA", "")),
                    QA_separator,
                    # str(do_QA_SR.get("fn_QA", "")),
                    get_colorized_string(str(do_QA_SR.get("fn_QA", ""))),
                    # str(do_QA_SR.get("QA_ID", "")),
                    get_colorized_string(str(do_QA_SR.get("QA_ID", ""))),
                    # str(do_QA_SR.get("QA_d8_hash", "")),
                    get_colorized_string(str(do_QA_SR.get("QA_d8_hash", ""))),
                    # "QA_d8_hash"     : QA_d8_hash,       # hash of (QA-Text + QA_tag)
                    # str(do_QA_SR.get("SR_TimeStamp", ""))
                ]
                if do_QA_SR["SR_TimeStamp"]: lines.append(str(do_QA_SR.get("SR_TimeStamp", "")))

                SR_entry = '\n'.join(lines) + '\n\n'
                f.write(SR_entry)
    return



def main():
    # gets all obsidian notes in >p_root< and makes flashcard - obsidian note (or anki connection).
    #
    # (Too complicated? Simply could have scanned all files for QA entries and written new QA-file?
    #  No: Because if QA in QA-file then there is a time stamp, that must be preserved.
    #  Therefor new QA-entries are appended to existing QA-file.)

    ini_path = 'tac.ini'
    load_config(ini_path)

    # find all obsidian notes in >p_root< or in >lo_subdir< of >p_root< (both are globals defined in >tac.ini<):
    lo_fn_note     = get_lo_fn_path_with_extension(p_root, lo_subdir, ext)

    # get >lo_do_QA_entry< == list of all QA-entries in *.md but not in QA-files (flashcard|anki| ...)
    #   n.b.: see composition of >do_QA< == Q&A-entry in the header of >tac.py<.
    lo_do_QA_entry = get_lo_QA_entry(lo_fn_note)

    # get_lo_fn_SR(): >lo_fn_SR< == name/s of QA_SR-file (file with SR flashcards).
    # Only this/these files are used by the Spaced Repetition Plugin in Obsidian to define flashcards.
    # Then get list >lo_do_QA_SR< of QA_SR entries:
    lo_fn_SR       = get_lo_fn_SR()
    lo_do_QA_SR    = get_lo_do_QA_SR(lo_fn_SR)

    # >lo_do_QA_SR< == list of dict of all QA in QA_SR-file (file with SR flashcards).
    # This are all the hitherto known QA-entries. It will be extended by new QA-entries from obsidian notes, if any.
    #   Every entry >do_QA_SR< has the
    #   desk-tag, the QA-text, the file name of origin, an ID (like : 'QA_ID_6CIRLAJZ_723fcae1'), and an unique hash.
    #   The plugin Space Repetition adds a time stamp (like: <!--SR:!2025-12-30,1,230-->)

    # >lo_do_QA_entry_new< == entries in obsidian notes not already in Spaced Repetition Flashcard File >lo_do_QA_SR<
    lo_do_QA_entry_new = get_lo_do_QA_entry_new(lo_do_QA_entry, lo_do_QA_SR)

    if lo_do_QA_entry_new:
        # Merge QAs from *.md and from QA_SR-file
        lo_do_QA_merged = get_lo_do_QA_merged(lo_do_QA_entry, lo_do_QA_SR)
        # There shouldn't be double entries. If so: exit()
        lo_do_QA_merged = check_duplicates_lo_do_QA(lo_do_QA_merged)

        if lo_do_QA_merged:   # new QA-entries -> update QA_SR_file
            write_QA_SR_file(lo_do_QA_merged)
        else:
            print(f'>write_QA_SR_file()<: \n  No new QA-entries')
    print("Total QA_flashcard entries:  ", len(lo_do_QA_SR))
    print("Total QA entries in md-notes:", len(lo_do_QA_entry))
    print("New   QA entries in md-notes:", cnt_new_QA)

if __name__ == "__main__":
    main()

# ToDo:
#  - Clean the regexs' in >load_config(ini_path)<
#  - remove the regexs' from >load_config(ini_path)<
#  - add anki support


# nb:
#  pip freeze > requirements.txt
#  .
#  find . -name '*.md' -exec sed -i -e 'QA_A/string_111/string_222/g' {} \;
#  .
#  >san.py<  transform in *.exe
#       >_ pip install pyinstaller
#       >_ pyinstaller --onefile -w 'san.py'
#  .
#  Obsidian community plugin: 'Shell commands' calls >san.exe< via shortcut
#    https://github.com/Taitava/obsidian-shellcommands
#  .
#    ctrl-P > Shell commands: Execute Split Into Annotation Notes (SAN)
#    >_Shell commands: (insert:)
#      "C:\Users\rh\Meine Ablage\obsidian_rh_GoogleDrive\zz_Templates_Scripts\Nunjucks_Templates\san.exe" "{{file_path:absolute}}"
#         /* Do not forget the quotation marks! */
#         /* with:  "{{file_path:absolute}}"  ==   "Gives the current file name with file ext" */
#      Output: Outputchannel for stdout: Notification balloon
#      Output: Outputchannel for stderr: Error balloon
