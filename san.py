'''
san.py == split_in_atomic_notes.py


This script serves to split a input obsidian_zotero s_content (aka 'source_note.md') into separate atomic notes.

2025-09-28
Zotero Item Types and Fields:
    https://www.zotero.org/support/kb/item_types_and_fields

github repository:
    https://github.com/rwrmanns/zotero-obsidian_split_atomic_notes

'''
import collections
import frontmatter
import glob
import hashlib
import inspect
import os
import re
import shutil
import sys
import yaml

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from io import StringIO
from typing import Optional, Collection
from tkinter import messagebox, Tk

path_data = Path(r"C:\Users\rh\Meine Ablage")

path_in   = Path(r"C:\Users\rh\Meine Ablage\obsidian_rh_GoogleDrive\01_Notes_Literature_Annotations")
path_out  = path_in

root = Tk()
root.withdraw()

stringIO = StringIO()

# Assume a obsidian >note.md< as: (note.frontmatter) followed by (note.body)
@dataclass
class Summary():
    def __init__(self, s_content: str = '', l_tag: list[str] = []):
        self.s_content = s_content
        self.l_tag     = l_tag

@dataclass
class Body(Summary):
    def __init__(self, s_content: str = '', l_tag: list[str] = []):
        self.summary   = Summary()
        self.s_content  = s_content
        self.l_tag      = l_tag

@dataclass
class Note(Body):
    def __init__(self, fn: str = '', path: Path = Path(), s_title: str = '', d_frontmatter: dict[str, str] = {}, s_content: str = '', l_tag: list[str] = []):
        self.fn              = fn
        self.p_fn            = path
        self.s_title         = s_title
        self.d_frontmatter   = d_frontmatter
        super().__init__(s_content, l_tag)

@dataclass
class Annotation(Note):
    pass


# https://stackoverflow.com/questions/651794/whats-the-best-way-to-initialize-a-dict-of-dicts-in-python#652226
def make_default_dict():
    return collections.defaultdict(make_default_dict)
    # >collections.default_dict< does not complain if key is missing.


s_mark_summary_begin       = r"%% begin summary %%"
s_mark_summary_end         = r"%% end summary %%"
s_mark_citation_title      = r"%% note citation title %%"
s_mark_citation_references = r"%% citation references %%"
s_mark_summary             = r"%% summary %%"
s_mark_connections         = r"%% connections %%"
s_mark_comment             = r"%% comment %%"
s_mark_tags                = r"%% tags %%"
s_mark_QA                  = r"%% QA %%"
s_mark_references          = r"%% references %%"

                             # %% Summary_R32EDMK3: Begin %%
rgx_summary_begin          = r"%% Summary_[A-Z0-9]{8}: Begin %%"
rgx_summary_end            = r"%% Summary_[A-Z0-9]{8}: End %%"
rgx_annotation_end         = r"%% Annotation_[A-Z0-9]{8}: End %%"
                           
# regex:
rgx_marks = re.compile(f"{re.escape(s_mark_summary_begin)}|"
                       f"{re.escape(s_mark_summary_end)}|"
                       f"{re.escape(rgx_summary_begin)}|"
                       f"{re.escape(rgx_summary_end)}|"
                       f"{re.escape(s_mark_citation_title)}|"
                       f"{re.escape(s_mark_citation_references)}|"
                       f"{re.escape(s_mark_summary)}|"
                       f"{re.escape(s_mark_connections)}|"
                       f"{re.escape(s_mark_comment)}|"
                       f"{re.escape(s_mark_tags)}|"
                       f"{re.escape(s_mark_QA)}|"
                       f"{re.escape(s_mark_references)}|"
                       f"{re.escape('%% s_content summary %%')}|"
                       f"{re.escape('%% s_content comment %%')}|"
                       f"{re.escape('%% s_content tags %%')}|"
                       f"{re.escape('%% s_content QA %%')}|"
                       f"{re.escape('%% s_content connections %%')}"
                       f"")

rgx_san_type      = r"annotation|summary"

# obsidian tags: not beginning with '#QA_'
# rgx_tag_obsidian  = re.compile(r'(#[A-Za-z0-9/_-]*[A-Za-z_/-][A-Za-z0-9/_-]*)', re.DOTALL)
rgx_tag_obsidian  = re.compile(r'#(?!QA_)\w+', re.DOTALL)
rgx_tag_obsidian  = re.compile(r'#(!QA_)\w+', re.DOTALL)
rgx_tag_obsidian  = re.compile(r'#(?!QA_)[a-zA-Z0-9]{2}[a-zA-Z0-9_-]{0,33}\b', re.DOTALL)
# pattern = r"#(?!QA_)[a-zA-Z0-9]{2}[a-zA-Z0-9_-]{0,33}\b"


# zotero tags (... allow white chars and a bunch of other special chars: filter these out to make obsidian tags)
# def filter_obsidian_tag_chars(str_in):
#     return ''.join(re.findall(r'[A-Za-z0-9/_-]', str_in))
rgx_tags_zotero_to_obsidian = lambda str_in: '#'.join(re.findall(r'[A-Za-z0-9/_-]', str_in))

# whole summary wo zotero hash
rgx_summary             = re.compile(r"%% begin summary %%(.*?)%% end summary %%", re.DOTALL)

# whole summary with zotero hash
rgx_summary             = re.compile(r"%% summary_[A-Z0-9]{8}: Begin %%.*?%% summary_[A-Z0-9]{8}: End %%", re.DOTALL)

# _all_ annotations
rgx_annotations_all     = re.compile(r"%% begin annotations %%(.*?)%% end annotations %%", re.DOTALL)

# single annotation
rgx_annotation          = re.compile(r"%% Annotation_[A-Z0-9]{8}: Begin %%.*?%% Annotation_[A-Z0-9]{8}: End %%", re.DOTALL)

# whole citation
# rgx_citation          = re.compile(        rf'^.*{re.escape(s_mark_citation_title)}.*{re.escape(s_mark_comment)}', re.MULTILINE)
rgx_citation            = re.compile(rf'^.*{re.escape(s_mark_citation_title)}.*{re.escape(s_mark_citation_references)}', re.MULTILINE)

# citation title
rgx_citation_title      = re.compile(rf'^#* *(.*){re.escape(s_mark_citation_title)}', re.MULTILINE)

# citation references
rgx_citation_references = re.compile(s_mark_citation_references + r"(.*?)" + s_mark_comment, re.DOTALL)

# annotation comment %%
rgx_annotation_comment  = re.compile(s_mark_comment + r"(.*?)" + s_mark_tags, re.DOTALL)

# annotation tags %%
rgx_annotation_tags     = re.compile(s_mark_tags + r"(.*?)" + s_mark_QA, re.DOTALL)

# annotation tags %%
rgx_annotation_tags     = re.compile(s_mark_tags + r"(.*?)" + s_mark_QA, re.DOTALL)

# annotation references %%
rgx_references          = re.compile(s_mark_references + r"(.*?)" + rgx_annotation_end, re.DOTALL)

rgx_page_number     = r"\[\(p\. \d{1,4}\)\]"

# zotero hash (unique for every annotation)
rgx_zotero_hash     = re.compile(r'Annotation_([A-Z0-9]{8}\b)|Summary_([A-Z0-9]{8}\b)', re.DOTALL)
#                                                                     Summary_R32EDMK3

# markdown - heading
rgx_heading         = re.compile(r'(^#* [^\n]*\n+)', re.MULTILINE)

# valid Windows filename (excluding reserved names)
rgx_windows_fn      = re.compile(r'^(?!^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$)(?!.*[\\/:*?"<>|])[^\\/:*?"<>|]{1,255}(?<![ .])$', re.IGNORECASE)
# Forbidden characters in Windows filenames
rgx_forbidden_chars = r'\\/:*?"<>|'


def get_date_time():
    s_date_iso  = datetime.now().isoformat()
    s_date_     = datetime.now().date().isoformat()
    s_time_     = datetime.now().strftime("%H:%M:%S")
    s_date_time = f"{s_date_} {s_time_}"
    return s_date_iso, s_date_time

def get_wc(s_text):
    lines = s_text.splitlines()
    n_lines = len(lines)
    n_words = sum(len(line.split()) for line in lines)
    n_chars = len(s_text)
    return f"{n_lines}/{n_words}/{n_chars}"


def get_content_hash(s_content):
    hash_algorithm = 'md5'
    hash_md5 = hashlib.md5()
    hash_md5.update(s_content.encode('utf-8'))
    s_hash_md5 = hash_md5.hexdigest()
    return hash_algorithm, s_hash_md5


def get_text_block(text: str, pattern_begin: str, pattern_end: str) -> Optional[str]:
    # Searches in >text< the first sequence of lines, 
    # that begins with >pattern_begin< and ends with >pattern_en<. 
    # Purge the marks >pattern_begin< and >pattern_en< from the resulting text.
    
    lines = text.splitlines()

    s_out_text = ''
    for i, line in enumerate(lines):
        if (s_out_text == '') and (pattern_begin in line):
            s_out_text  = line
        elif pattern_end in line:
            break
        elif (s_out_text !=  ''):
            s_out_text += '\n' + line

    s_out_text = s_out_text.replace(pattern_begin, '')
    s_out_text = s_out_text.replace(pattern_end, '')

    return s_out_text

def get_text_wo_marks(s_text):
    # Remove all occurrences of strings in l_str from s_text
    text_wo_marks = rgx_marks.sub('', s_text)
    return text_wo_marks


def get_value_from_dict(d_dict: dict, s_keys: str) -> Optional[str]:
    # >d_dict< may be a nested dict. Transform s_keys in sequence of keys.
    # If keys exist return the corresponding value of d_dict.
    # print (get_value_from_dict("['key_11']['key_21']"))
    # print (get_value_from_dict("['key_3']"))
    # print (get_value_from_dict("['key_13']"))

    keys = re.findall(r"\['?([^']+)'\]?", s_keys)
    d_current = d_dict
    for key in keys:
        if isinstance(d_current, dict) and key in d_current:
            d_current = d_current[key]
        else:
            return None
    return d_current

def get_value_from_dict_of_path(p_fn: str, s_keys: str) -> Optional[str]:
    # If >p_fn< is a path of a >note.md<, then get the val of an entry in frontmatter (frontmatter is a dict).
    if Path(p_fn).is_file():
        _, d_frontmatter, _ = get_note_source_parts(p_fn)
        return get_value_from_dict(d_dict = d_frontmatter, s_keys = s_keys)
    else:
        return None

def merge_without_duplicates(l_word_1, l_word_2):
    """ Input: two lists of (single) words
        Remove item in >l_word_2< if present in both lists
        return sorted sum of lists
    """    
    set_word_1 = set(l_word_1)
    # Remove items from l_word_2 that are also in l_word_1
    filtered_l_word_2 = [word for word in l_word_2 if word not in set_word_1]
    # Combine l_word_1 and the filtered l_word_2
    result = set_word_1 | set(filtered_l_word_2)
    return sorted(result)

def backup_note_source_with_timestamp(p_fn_in):
    """
    Renames p_fn_in.md to fn_in_YYYY-MM-DD_HHMMSS.md.
    Returns the p_fn_backup filename.
    """
    base, ext = os.path.splitext(p_fn_in)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    p_fn_backup = f"{base}_{timestamp}{ext}"

    shutil.copy2(p_fn_in, p_fn_backup)

    print(f"File:   {os.path.basename(p_fn_in)} updated:")
    print(f"Backup: {os.path.basename(p_fn_backup)}.")

    return p_fn_backup


def backup_note_source(p_fn_note_source):
    """
    In >note_source<
    >s_content< can be changed if:
     - new version is imported from zotero
     - new version was  changed by obsidian.

    If new version comes from zotero => the following keys in frontmatter are lacking (among others):
     - frontmatter [san][content_hash_algorithm]
     - frontmatter [san][content_hash]
     - frontmatter [san][content_word_count]
     => create these keys, backup and save >note_source<

    If new version results by modifications by obsidian => the following keys in frontmatter have wrong values:
     - frontmatter [san][content_word_count]
     - frontmatter [san][content_hash]
     => update these keys, backup and save >note_source<
    """

    # Get frontmatter and content
    _, d_frontmatter_fs, s_content_fs    = get_note_source_parts(p_fn_note_source)
    # actual hash s_content of >note_source< in file system:
    content_hash_algorithm, content_hash = get_content_hash(s_content_fs)

    b_keys_vals_updated = False
    b_key_exists = get_value_from_dict(d_frontmatter_fs, "['san']['content_hash']")
    if not b_key_exists:
        # key does not exist => create keys with their values.
        d_frontmatter_fs["san"]["content_hash_algorithm"] = content_hash_algorithm
        d_frontmatter_fs["san"]["content_hash"]           = content_hash
        d_frontmatter_fs["san"]["content_word_count"]     = get_wc(s_content_fs)
        b_keys_vals_updated = False
    elif (content_hash != d_frontmatter_fs["san"]["content_hash"]):
        # vals are not true => update keys with their values.
        d_frontmatter_fs["san"]["content_hash_algorithm"] = content_hash_algorithm
        d_frontmatter_fs["san"]["content_hash"]           = content_hash
        d_frontmatter_fs["san"]["content_word_count"]     = get_wc(s_content_fs)
        b_keys_vals_updated = False

    if b_keys_vals_updated:
        # Write the modified body to the original file name
        with open(p_fn_note_source, 'w', encoding='utf-8') as f:
            f.write(content)

        p_fn_note_source_backup = backup_note_source_with_timestamp(p_fn_note_source)

    return


def sanitize_and_check_windows_filename(s_fn):
    """
    check if string >s_fn< is valid windows filename
    if not try to repair/sanitize filename
    returns valid filename and boolean if fn_note_source is valid
    """
    # Replace spaces with underscores
    sanitized_s_fn = s_fn.strip().replace(' ', '_')
    # Remove forbidden characters
    sanitized_s_fn = re.sub(f'[{re.escape(rgx_forbidden_chars)}]', '', sanitized_s_fn)
    # summary: *_000_.md  -> *_000.md
    sanitized_s_fn = re.sub(f'_000_.md', '_000.md', sanitized_s_fn)
    # Check against regex
    b_valid_fn = bool(rgx_windows_fn.match(sanitized_s_fn))
    return sanitized_s_fn


def compose_note_fn(note_source_fn, s_idx, title):
    ##########################################################################################
    # Compose p_fn_in of new atomic s_content:
    # base     == fn_note_source  of source s_content
    # >title<  == citation_title or '' (summary)
    # >hash<   == citation_hash  or '' (summary)
    name, ext = os.path.splitext(note_source_fn)
    # try to append heading of first section  s_citation_title == s_citation_title
    note_annotation_fn = f"{name}_{s_idx}_{title}{ext}"
    note_annotation_fn = sanitize_and_check_windows_filename(note_annotation_fn)
    return note_annotation_fn


def check_and_update_s_content_hash (l_p_fn_note) -> str:
    """
    If content changed:
      Create copy of file && increment version.
      l_p_fn_note_new (str) : list of paths of file with fn beginning with citekey.
    """

    for p_fn_note in l_p_fn_note:
        # Get values >d_frontmatter< and >s_content< of >p_fn_note< from file system:
        _, d_frontmatter_fs, s_content_fs = get_note_source_parts(p_fn_note)
        _, content_hash_fs_real           = get_content_hash(s_content_fs)  # actual hash of content of s_content in file system

        # Check if the hash-value of content in >s_content< corresponds to the hash reported in frontmatter of >s_content<:
        # If not => the s_content has been modified since being written by >san.py<
        #           => in frontmatter: update hash of content to real value,
        #           => in frontmatter: update version,
        #           => write new version of s_content.

        content_hash_fs_frontmatter = d_frontmatter_fs['san']['content_hash']
        if content_hash_fs_frontmatter != content_hash_fs_real:

            # 1. update >content_hash< with real value:
            d_frontmatter_fs['san']['content_hash'] = content_hash_fs_real

            #  note_origin
            note_origin_tmp = d_frontmatter_fs['san']['note_origin']
            del(d_frontmatter_fs['san']['note_origin'])
            d_frontmatter_fs['san']['note_origin'] = 'note_obsidian'

            #  version:
            version = d_frontmatter_fs['san']['note_version']
            d_frontmatter_fs['san']['note_version'] = version + 1

            s_content = get_dict_to_yaml_str(d_frontmatter_fs)
            s_content += '\n'
            s_content += s_content_fs

            try:
                with open(p_fn_note, "w", encoding="utf-8") as f_out:
                    f_out.write(s_content)
            except Exception as e:
                msg = f"Function >{inspect.currentframe().f_code.co_name}<:\nFailed to save new version of file: \n{os.path.basename(p_fn_note)}\n{e}"
                # msg = f"Function >do_save_existing_file_versioning_fn()<:\nFailed to save new version of file: \n{os.path.basename(p_fn_note)}\n{e}"
                messagebox.showinfo("Save Error", msg)
    return None


def do_save_note_source_with_flag(note_source, version):
    """
    Saves >s_content< and adds a flag to the filename stem.
    If saving fails, asks the user whether to try again via a Tkinter messagebox.
        s_content () : new s_content from source
    Returns:
        Path object of the new file if successful, otherwise None
    """

    p_fn_note = note_source.p_fn_note
    base_path = Path(p_fn_note)

    # Save file with same file name extended by flag
    # Change >title< in frontmatter
    s_flag = f"__updated"
    title_old = note_source.d_frontmatter['title']
    title_new = title_old + s_flag + f"   (... may be newer than '{title_old}')"

    fn_note_with_flag   = f"{base_path.stem}{s_flag}{base_path.suffix}"
    p_fn_note_with_flag = base_path.with_name(fn_note_with_flag)

    note_source.d_frontmatter['title']               = title_new
    note_source.d_frontmatter['san']['note_status']  = 'undefined'
    note_source.d_frontmatter['san']['note_version'] = version      # should be identical to version of note_in_fs

    try:
        s_note  = get_dict_to_yaml_str(note_source.d_frontmatter)
        s_note += '\n'
        s_note += note_source.s_content
        with open(p_fn_note_with_flag, "w", encoding="utf-8") as f_out:
            f_out.write(s_note)
        return p_fn_note_with_flag
    except Exception as e:
        msg = f"Function >{inspect.currentframe().f_code.co_name}<:\nFailed to save versioned file: \n{os.path.basename(p_fn_note_with_flag)}\n{e}"
        messagebox.showinfo("Save Error", msg)
        return None


def do_write_atomic_note(note_source, l_p_fn_note, cnt_notes_written) -> int :
    """
    Writes >s_content< == note_(summary|annotation) coming from zotero_note.
    Parameters:
        note_source (Note): total content of future actual_note (e.g., 'actual_note.md').
        l_p_fn_note : list of paths of note_annotation akready written to file system.
        cnt_notes_written ():
    Returns:
        cnt_notes_written (incremented if a s_content was written to file system).
    """

    result = ''

    # no previous version of note_(summary|annotation) found => very first writing of >s_content<
    if not Path(note_source.p_fn).is_file():
        # put the s_content together: join frontmatter and content to s_note == text of note_fs.
        s_note  = get_dict_to_yaml_str(note_source.d_frontmatter)
        s_note += '\n'
        s_note += note_source.s_content
        with open(note_source.p_fn, "x", encoding="utf-8") as f_out:
            f_out.write(s_note)
        p_fn_note    = note_source.p_fn

    # there are previous versions of >s_content< with file name >s_content.p_fn< in file system:
    # the most recent version of >s_content< (== note_summary|annotation) in file system are in >l_p_fn_note<
    else:
        # >l_p_fn_note<: list of fn, that begin with zotero-citekey of s_content.
        # Search note_fs in >l_p_fn_note< that has a >san_zotero_hash< identical to that of >s_content<:
        #  => >p_fn_note< == latest previous version of s_content  (earlier versions are not in >l_p_fn_note<).

            # ps: The indirect reference to notes in the fs (via ) is due to the wish to identify the notes not by filename,
            #   but by the (unique) hash zotero has given to the note_fs respectively the single annotations.
            # In the actual version this possibility of reference is not yet used - may be in future versions.

        # >l_p_fn_note< == list of filenames beginning with zotero hash.
        # >*_fs<        == indicates "note_ in file system"

        # Search file: >xyz_NNN_(summary|annotation).md< in fs with identical >zotero_hash< (== note_summary|annotation)
        for p_fn_note in l_p_fn_note:
            _, d_frontmatter_fs, s_content_fs = get_note_source_parts(p_fn_note)
            #  rgx_san_type = r"annotation|summary"
            if ((d_frontmatter_fs['san']['type'] in rgx_san_type)
                    and (d_frontmatter_fs['san']['zotero_hash'] == note_source.d_frontmatter['san']['zotero_hash'])):
                # get latest version-number of s_content
                version_latest = d_frontmatter_fs['san']['note_version']
                # get path of latest version of actual note_fs  ==  path of s_content
                break

        # >p_fn_note< == path of s_content with fitting >zotero_hash< (of annotation|summary) == previous version of >s_content<
        note_fs                = Note()                 # == s_content in memory corresponding to note_fs in file system.
        note_fs.p_fn_note      = p_fn_note
        note_fs.d_frontmatter  = d_frontmatter_fs
        note_fs.s_content      = s_content_fs

        # In _written_ note_fs: if (>content_hash< !=  content_hash_source_fs)
        #  => >note_fs.md< has been changed in obsidian since been written by >san.py<.
        #  nota bene: note_fs == s_content written in fs.
        content_hash_fs        = get_value_from_dict(d_dict = d_frontmatter_fs , s_keys = "['san']['content_hash']")          # hash of note_in_fs: actual hash
        content_hash_source_fs = get_value_from_dict(d_dict = d_frontmatter_fs , s_keys = "['san']['content_hash_source']")   # hash of note_in_fs: when written by >san.py<
        version_fs             = get_value_from_dict(d_dict = d_frontmatter_fs , s_keys = "['san']['note_version']")               # version of note_in_fs

        d_frontmatter_src = note_source.d_frontmatter
        content_hash_source    = get_value_from_dict(d_dict = d_frontmatter_src, s_keys = "['san']['content_hash']")          # hash of note_in_fs: when written by >san.py<

        # >note_fs< is identical to the first saved version
        b_note_fs_unchanged = (content_hash_fs == content_hash_source_fs)

        # in d_frontmatter of >note_fs<: the entry of hash of note_source is different from
        # the real hash of the new >note_source<. This means: the most recent version of >note_source<
        # can not be the source of >note_fs<.
        # This indicates a conflict of versions: which is the desired one? >note_source< or >note_fs<
        b_hashes_identical  = (content_hash_source == content_hash_source_fs)

        # if content_hash_fs == content_hash_source_fs:  # >note_fs.md< or >note_source< has been changed
        if b_note_fs_unchanged and b_hashes_identical:  #
            # >note_source< has not changed => (i.e. source of >note_fs.md< is unchanged) there aren't any conflicting versions.
            result = 'ok'
        else:
            if b_hashes_identical:
                result = 'ok'
            else:
                # Here's the problem: there are two conflicting versions of same note:
                # the new >note_source< (from note_zotero) and >note_fs< (already written to file system).
                # Prove: >content_hash_source< in >note_fs<  differs from the content has of new >note_source<
                #
                # It's not possible to decide which of these conflicting versions is the valid one.
                # => both of them have to be preserved.
                # => 1. keep  >note_source_fs< unchanged and with unchanged filename.
                #    2. write >s_content<    to fs with filename with flag '_SOURCE'

                # The difference in hashes will cause the identical conflict of notes the next time the
                # identical >note_source< is checked to be written.
                # Therefor the value of >note_fs<.frontmatter['san']['content_hash_source'] is set to
                # >note_source<.frontmatter['san']['content_hash_source'], to prevent this recurrent situation.
                # If this hash is encountered the next time, the conflict can be ignored.

                # content_hash_source == content_hash_source_fs
                note_fs.d_frontmatter['san']['content_hash_source'] = content_hash_source
                s_note  = get_dict_to_yaml_str(note_fs.d_frontmatter)
                s_note += '\n'
                s_note += note_fs.s_content
                with open(note_fs.p_fn_note, "w", encoding="utf-8") as f_out:
                    f_out.write(s_note)

                note_source.p_fn_note = p_fn_note    # will be updated in >do_save_note_source_with_flag()<
                p_fn_note             = do_save_note_source_with_flag(note_source, version_fs)

    if (p_fn_note != '') and (result != 'ok'):
        cnt_notes_written += 1
        print(f'Note written to: >{os.path.basename(p_fn_note)}<.')
    elif (result == 'ok'):
        pass
    else:
        print(f'{note_summary.fn =}: Error writing {os.path.basename(p_fn_note)}')
    return cnt_notes_written


def get_note_source_parts(p_note_source_fn):
    # From s_content >p_fn_note_source<: Extract s_citation_title, frontmatter, and content
    try: # Load the .md file with frontmatter
        # Python Frontmatter: Parse and manage posts with YAML frontmatter
        post = frontmatter.load(p_note_source_fn)
        if not post.metadata:
            mssge_1 = f"ERROR: get_note_source_parts({p_note_source_fn})"
            mssge_2 = "No frontmatter properties found."
            exit(f" {mssge_1}: {mssge_2}")
    except FileNotFoundError:
        mssge_1 = f"File not found: {p_note_source_fn}"
        exit(f" {mssge_1}")
    except Exception as e:
        mssge_1 = f"Error reading file: {e}"
        exit(f" {mssge_1}")

    # In s_content: Extract s_citation_title, frontmatter, and body
    s_title       = post.metadata.get("title", "No s_citation_title found")
    d_frontmatter = post.metadata   # == dictionary
    s_content     = post.content    # == string

    return s_title, d_frontmatter, s_content

def get_dict_to_yaml_str(d_frontmatter: dict) -> str:
    """
    Convert a dictionary to a YAML-formatted string suitable for Obsidian frontmatter.
    It wraps the generated YAML between triple-dash '---' lines.
    """
    # Define custom representer for datetime.date to ensure proper YAML conversion
    def date_representer(dumper, data):
        return dumper.represent_scalar('tag:yaml.org,2002:timestamp', data.isoformat())

    yaml.add_representer(datetime.date, date_representer)

    # Dump dictionary as YAML with readable formatting
    yaml_str = yaml.dump(
        d_frontmatter,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False
    )

    # Wrap YAML in triple dashes for Obsidian frontmatter
    return f"---\n{yaml_str}---"


def compose_and_write_atomic_note_summary(note_summary, note_source, idx, l_p_fn_note, b_do_write, cnt_notes_written):
    # https://lingodigest.com/the-typo-that-became-a-word-the-story-of-summary/ 
    # 1. Compose note_summary == (compose content) + (compose frontmatter)
    # 2.   (frontmatter needs >s_content< to calculate get_wc)
    s_idx = f"{idx:03}"  # index der Annotation

    # #############################################################################################
    # compose and write new >note_summary<

    # get filename of note_summary:
    s_note_title           = "Summary"
    # note_summary.fn       = compose_note_fn(note_source.note_source_fn, s_idx, s_note_title)
    note_summary.fn       = compose_note_fn(note_source.fn, s_idx, s_note_title)
    note_summary.p_fn     = os.path.join(path_out, note_summary.fn)

    match = re.search(rgx_zotero_hash, note_summary.s_content);
    if match:
        s_summary_zotero_hash = match.group()[-8:]
    else:
        s_summary_zotero_hash = 'Error???'

    # #############################################################################################
    # compose note_summary
    # note_summary.s_content == jeder _Text_, der in s_content nach frontmatter und vor den annotations kommt .
    # note_summary.s_content ... wird später in >note_summary.md_text< eingefügt, wobei
    # >note_summary.md_... <  == der endgültige *.md Text der s_content ist.

    # No \n at beginning, no \n at end!
    s_content  = '___' + '\n'
    s_content += note_summary.s_content_tags + '\n'
    s_content += "___" + '\n'

    s_content += "##### "  + note_source.d_frontmatter['zotero_fields']['title'] + '\n\n'
    s_content += "###### " + note_summary.d_frontmatter['zotero_fields']['authors'] # + '\n'
    s_content += get_text_wo_marks(note_summary.s_content) # + '\n'

    s_content += "___" + '\n'
    s_content += note_summary.s_references


    # %% Summary_R32EDMK3: Begin %%
    s_content = re.sub(rgx_summary_begin, '', s_content, flags=re.DOTALL)
    note_summary.s_content = get_text_wo_marks(s_content)

    # get s_note_source_citekey for atomic s_content
    word_count = get_wc(s_content)
    d_frontmatter = compose_note_frontmatter(note_summary.s_content, note_source.d_frontmatter,
                                             s_summary_zotero_hash, word_count,
                                             s_note_title)
    note_summary.d_frontmatter = d_frontmatter

    if b_do_write and note_summary.s_content:
        cnt_notes_written = do_write_atomic_note(note_source=note_summary, l_p_fn_note=l_p_fn_note,
                                                 cnt_notes_written=cnt_notes_written)
    return cnt_notes_written


def compose_and_write_atomic_note_annotation(note_source, l_summary_tags, idx, s_annotation, l_p_fn_note, b_do_write,
                                             cnt_notes_written):

    s_idx = f"{idx:03}"  # index der Annotation

    # #############################################################################################
    # Structure of every annotation:
    #         %% Annotation_WQNWCN6K: Begin %%
    #         ###### Überschrift_WQNWCN6K                   %% citation %%
    #         lorem ipsum dolor sit amet,
    #            etc...
    #         ### Kommentar                                 %% comment %%
    #         ...
    #         ### Tags                                      %% tags %%
    #         ...
    #         ### QA                                        %% QA %%
    #         ...
    #         %% Annotation_WQNWCN6K: End %%

    # Print extracted annotation with formatting
    # print(f"\nAnnotation {idx}:")
    #
    # annotation: s_note_title == md heading with zotero hash of annotation
    # becomes >s_content.title< of new >s_content<
    # >### This_is_Title    %% s_content citation title %%<   =>   >This_is_Title<
    s_note_title = rgx_citation_title.search(s_annotation).group(1).strip()
    s_note_title = sanitize_and_check_windows_filename(s_note_title)
    #
    # annotation: extract zotero_hash of annotation s_content; .group(1) == Hash
    # >%% Annotation_ZKHQG4B7: Begin %%>  => >ZKHQG4B7<
    s_annotation_zotero_hash = rgx_zotero_hash.search(s_annotation).group(1)
    #

    # annotation: get list of tags:
    # becomes (list of all tags within annotation + list of tags of summary) of new >s_content<

    l_tag_annotation = rgx_tag_obsidian.findall(s_annotation)
    # remove every tag in >s_content< (can be everywhere) - they will later be summarized under >### tags<
    for tag in l_tag_annotation:
        s_annotation = s_annotation.replace(tag, "")
    # Merge >l_tag_annotation< and >l_summary_tags< == tags in >summary< to share with every annotation - note
    l_tag_all = merge_without_duplicates(l_summary_tags, l_tag_annotation)
    s_tags = '' + ' '.join(l_tag_all)
    if not s_tags: s_tags = 'Tags: '

    #
    # annotation: citation      => becomes >citation< of new >s_content<
    s_citation       = get_text_block(text=s_annotation, pattern_begin=s_mark_citation_title, pattern_end=s_mark_citation_references)
    #
    # annotation: references inside citation => becomes >citation_refs< of new >s_content<
    s_citation_refs   = get_text_block(text=s_annotation, pattern_begin=s_mark_citation_references, pattern_end=s_mark_comment)
    #
    # annotation: comment       => becomes >comment< of new >s_content<
    s_comment        = get_text_block(text=s_annotation, pattern_begin=s_mark_comment, pattern_end=s_mark_tags)
    #
    # annotation: QA            => becomes >QA< of new >s_content<
    s_QA            = get_text_block(text=s_annotation, pattern_begin=s_mark_QA, pattern_end=s_mark_references)
    #
    # annotation: references    => becomes >references< of new >s_content<
    s_references    = get_text_block(text=s_annotation, pattern_begin=s_mark_references, pattern_end=rgx_annotation_end)
    #

    # #############################################################################################

    note_annotation = Note()  # create new >note.md<

    # #############################################################################################
    # compose s_content
    # All annotations of >s_annotations_all< (>s_annotations_all<) are elements in >l_s_annotation<.
    # s_content == every _text_ after frontmatter.
    # s_content ... is the second part of the resulting notes.

    s_source_title = note_source.d_frontmatter['zotero_fields']['title']
    s_authors      = note_source.d_frontmatter['zotero_fields']['authors']

    # No \n at beginning, no \n at end!
    s_content   = '___' + '\n'
    s_content  += s_tags + '\n'
    s_content  += "___" + '\n'

    s_content  += "##### "  + s_source_title + '\n\n'
    s_content  += "###### " + s_authors + '\n'
    s_content  += s_citation + '\n'
    s_content  += s_citation_refs + '\n'
    s_content  += "___" + '\n'
    s_content  += s_comment + '\n'
    s_content  += s_QA + '\n'
    s_content  += s_references
    s_content  += "___"

    note_annotation.s_content  = get_text_wo_marks(s_content)

    # get s_note_source_citekey for atomic s_content
    word_count = get_wc(s_content)
    d_frontmatter = compose_note_frontmatter(note_annotation.s_content, note_source.d_frontmatter,
                                             s_annotation_zotero_hash, word_count,
                                             s_note_title)

    note_annotation.d_frontmatter = d_frontmatter

    # get filename and path of s_content
    fn    = compose_note_fn(note_source.fn, s_idx, s_note_title)
    note_annotation.p_fn  = os.path.join(path_out, fn)

    if b_do_write and note_annotation.s_content:
        cnt_notes_written = do_write_atomic_note(note_source=note_annotation, l_p_fn_note=l_p_fn_note,
                                                 cnt_notes_written=cnt_notes_written)
    return cnt_notes_written


def compose_note_frontmatter(s_content: str, d_frontmatter_source, s_zotero_hash: str,
                             s_word_count: str, s_note_title: str) -> any:
    # #############################################################################################
    # compose d_frontmatter for atomic s_content
    # #############################################################################################
    d_frontmatter = d_frontmatter_source
    #
    d_annotations = dict({'id':s_zotero_hash})
    d_frontmatter['zotero_fields']['d_annotations'] = d_annotations
    #
    # Versioning: hash_algorithm, hash_digest, date, version, get_wc  of >s_content<
    d_frontmatter['san']['content_word_count'] = s_word_count
    #
    # hash of s_content to see changes
    hash_algorithm, content_hash = get_content_hash(s_content)

    # frontmatter of s_content
    d_frontmatter['san']['content_hash_algorithm'] = hash_algorithm
    # >d_frontmatter['san']['content_hash']< will be updated by function >check_and_update_s_content_hash()<. 
    d_frontmatter['san']['content_hash']           = content_hash   # == hash of s_content
    d_frontmatter['san']['content_hash_source']    = content_hash
    #
    # date and time
    s_date_iso, s_date_time = get_date_time()
    d_frontmatter['san']['note_date_time']     = s_date_time
    #
    d_frontmatter['san']['source']             = d_frontmatter_source['zotero_fields']['citekey']
    d_frontmatter['san']['source_zotero_hash'] = d_frontmatter_source['zotero_fields']['key']
    d_frontmatter['san']['zotero_hash']        = s_zotero_hash
    #
    d_frontmatter['san']['type']               = 'annotation'
    #
    # move entry >d_frontmatter_fs['san']['note_origin']< to the end of frontmatter:
    note_origin_tmp = d_frontmatter['san']['note_origin']
    del (d_frontmatter['san']['note_origin'])
    d_frontmatter['san']['note_origin']        = note_origin_tmp
    #
    d_frontmatter['san']['note_status']        = 'valid'
    # note_version = 1; if there is another version >do_write_atomic_note()< will modify it.
    d_frontmatter['san']['note_version']       = 1
    #
    d_frontmatter['title']                     = s_note_title
    #
    return d_frontmatter


def split_note_source_in_atomic_notes(p_note_source_fn: Path):
    # >s_content<    ==               frontmatter + summary + annotation * n   ... s_content from zotero with annotations
    # is splitted in:  :   summary +  (frontmatter + annotation) * n

    b_do_write = False
    b_do_write = True   # write atomic notes

    # Define file_in p_fn: Pfad in dem die input-file: *.md Note ist.
    note_source_fn    = os.path.basename(p_note_source_fn)

    note_source       = Note()
    note_source.fn    = note_source_fn
    note_source.p_fn  = p_note_source_fn

    # Assume source s_content as input: a obsidian s_content.md as: (s_content.frontmatter) followed by (s_content.body)
    # Get: s_title, s_note_source_citekey, s_content ... of source s_content
    s_title, d_frontmatter, s_content = get_note_source_parts(p_note_source_fn)

    note_source.s_title       = s_title
    note_source.d_frontmatter = d_frontmatter
    note_source.s_content     = s_content

    # obsidian_zotero link to source s_content
    citekey                     = note_source.d_frontmatter['zotero_fields']['citekey']
    note_source.s_link          = f"[[{citekey}]]({note_source.d_frontmatter['zotero_fields']['desktopURI']})"
    # das ist die Referenz auf die gesamte Quelle, aber es sollte die auf die Annotation sein.
    # Diese muss also aus der Note eruiert werden, nicht aus s_note_source_citekey, dort ist sie nicht zu finden.
    note_source.s_link          = f"[Go to annotation]({note_source.d_frontmatter['zotero_fields']['desktopURI']})"
    note_source.s_link_obsidian = f'[@{citekey}]'

    # write s_content: note_summary (aka summary)
    # #############################################################################################
    # summary   == first part of >s_content< after >frontmatter<  before >annotations<
    # s_summary ==     string of >s_content< after >frontmatter<  before >annotations<
    s_summary    = get_text_block(text=note_source.s_content, pattern_begin=s_mark_summary_begin, pattern_end=s_mark_references)
    s_references = get_text_block(text=note_source.s_content, pattern_begin=s_mark_references, pattern_end=s_mark_summary_end)


    summary = Summary()          # summary of s_content

     # note_summary == s_content from summary
    note_summary = Note()       # note_summary/summary s_content based on summary of source s_content
    note_summary.d_frontmatter  = note_source.d_frontmatter
    note_summary.s_content_tags = get_s_tags_in(s_content)       # str:  all tags in note
    note_summary.s_content      = get_text_wo_marks(s_summary)   # == s_summary w/o tags
    note_summary.s_references   = s_references

    global path_out
    path_out = Path(os.path.join(path_in, citekey + '_Annotations'))
    if not os.path.exists(path_out):
        os.makedirs(path_out)

    # get latest versions of all atomic notes in file system of >s_content<
    l_p_fn_note = get_l_fn_note_with_citekey(note_source.d_frontmatter['zotero_fields']['citekey'])
    # update >content_hash< of _all_ notes in >l_p_fn_note< == all notes with fn beginning with citekey.
    check_and_update_s_content_hash(l_p_fn_note)

    idx = 0 ; cnt_notes_written = 0
    cnt_notes_written = compose_and_write_atomic_note_summary(note_summary, note_source, idx, l_p_fn_note, b_do_write,
                                                              cnt_notes_written)


    # #############################################################################################
    # now: annotations
    # #############################################################################################
    # annotations
    # s_annotations_all == one long string with all annotations in s_content ... .
    # in >s_content< surrounded by: >begin annotations< ... >end annotations<.
    s_annotations_all = re.search(rgx_annotations_all, s_content).group()

    #  In s_annotations_all: Find all annotations:
    #     >rgx_annotation< returns everything from beginning to end of every single annotation,
    #     ie: citation, comment, tags, QA (if present).

    # l_s_annotation == list of all annotations == >s_annotations_all< splitted
    l_s_annotation = re.findall(rgx_annotation, s_annotations_all)

    # ToDo:
    #  eliminate parameter >fn_note_source<, because already existing as >s_content.fn<
    l_summary_tags = get_l_tag_in(s_summary)        # list: all tags in summary
    for idx, s_annotation in enumerate(l_s_annotation, start=1):
        cnt_notes_written = compose_and_write_atomic_note_annotation(note_source, l_summary_tags, idx, s_annotation,
                                                                     l_p_fn_note, b_do_write, cnt_notes_written)

    print('=' * 25)
    print(f"{cnt_notes_written}: Notes written.")
    print('=' * 25)

    return cnt_notes_written


def get_l_tag_in(s_summary: str) -> list:
    l_tag = sorted(rgx_tag_obsidian.findall(s_summary))
    return l_tag


def get_s_tags_in(s_summary: str) -> str:
    # summary.l_tag == list of all tags inside s_summary
    l_tag = get_l_tag_in(s_summary)
    for tag in l_tag:
        # remove every tag in >s_summary< (can be everywhere) - they will later be summarized under >### tags<
        s_summary = s_summary.replace(tag + ' ', "")
    l_tag = list(sorted(set(l_tag)))
    # s_content_tags == one string of all tags (sorted)
    s_tags = '' + ' '.join(l_tag)

    if not s_tags: s_tags = 'Tags: '
    return s_tags


def get_l_fn_note_with_citekey(s_note_source_citekey: str) -> list[str]:
    '''
    Find all atomic notes with fn beginning with >s_note_source_citekey<.
    If there are multiple versions of an atomic s_content, filter the latest/highest version...
       Try to insert the filename, version etc into a double nested dict.
       If there is a older version inside the double nested dict substitute it by the newer one.
    '''

    # l_p_fn_note = list of all path_fn in >path_out< where fn begins with citekey (of zotero s_content source)
    p_path     = os.path.join(path_out, s_note_source_citekey + '_*')
    l_p_fn_all = glob.glob(p_path)
    # == all notes in >path_out< with fn beginning with citekey
    # == >citekey_XYZ_vs_NNNN.md< or >citekey_XYZ.md<

    # >d_d_< means double nested dict.
    d_d_note_latest = make_default_dict()

    # kind of complicated ... get the most recent version in >l_p_fn_all< of s_content with fn == >citekey_XYZ_vs_NNNN.md<.
    # Should be simply >citekey_XYZ.md<.
    for p_fn in l_p_fn_all:
        _, d_frontmatter, s_content = get_note_source_parts(p_fn)

        if (d_frontmatter['san']['type'] in rgx_san_type):  #  >rgx_san_type< ==  = r"annotation|summary"
            # check if s_content in >d_d_note_latest<:
            zotero_hash = d_frontmatter['san']['zotero_hash']
            try:
                # if s_content in >d_d_note_latest< then there is the version of s_content too:
                version = d_d_note_latest[f'{zotero_hash}']['note_version']
                if version:  # check if latest version in >d_d_note_latest< ?
                    if ((version < d_frontmatter['san']['note_version']) and
                            d_d_note_latest[f'{zotero_hash}']['source_zotero_hash'] and
                            d_d_note_latest[f'{zotero_hash}']['zotero_hash']):
                        # no: replace by newer version:
                        # delete old one
                        d_d_note_latest.pop(f'{zotero_hash}')
                        # insert newer version:
                        d_d_note_latest[f'{zotero_hash}']['source_zotero_hash'] = d_frontmatter['san']['source_zotero_hash']
                        d_d_note_latest[f'{zotero_hash}']['zotero_hash']        = d_frontmatter['san']['zotero_hash']
                        d_d_note_latest[f'{zotero_hash}']['p_fn']               = p_fn
                        d_d_note_latest[f'{zotero_hash}']['note_version']       = d_frontmatter['san']['note_version']
                else:
                    # since there is no version => there is no entry => add entry
                    d_d_note_latest[f'{zotero_hash}']['source_zotero_hash'] = d_frontmatter['san']['source_zotero_hash']
                    d_d_note_latest[f'{zotero_hash}']['zotero_hash']        = d_frontmatter['san']['zotero_hash']
                    d_d_note_latest[f'{zotero_hash}']['p_fn']               = p_fn
                    d_d_note_latest[f'{zotero_hash}']['note_version']       = d_frontmatter['san']['note_version']
            # KeyError shouldn't occur since >d_d_note_latest< is an >collections.defaultdict()< where keys are always present
            except KeyError:
                d_d_note_latest[f'{zotero_hash}']['source_zotero_hash'] = d_frontmatter['san']['source_zotero_hash']
                d_d_note_latest[f'{zotero_hash}']['zotero_hash']        = d_frontmatter['san']['zotero_hash']
                d_d_note_latest[f'{zotero_hash}']['p_fn']               = p_fn
                d_d_note_latest[f'{zotero_hash}']['note_version']       = d_frontmatter['san']['note_version']

    l_p_fn_note = []
    if d_d_note_latest:
        for k_san_zotero_hash, d_key_val in d_d_note_latest.items():
            for key, val in d_key_val.items():
                if key == 'p_fn':
                    l_p_fn_note.append(val)

    return l_p_fn_note


"""
obsidian:
Obsidian 'Zotero Integration Plugin':
   >san_nunjucks.nunjucks< (== >san_nunjucks.md<)  template to import >source note< from zotero.

Obsidian 'Shell commands plugin':
   calls >san.exe< (== >split annotation note.py<) to split >source note< into obsidian atomic notes.    

------------------------------------------------------------------------------------------------------------------------

zotero-Zitationen sind erstmals lediglich bibliographische Quellenangaben + evtl. die gesamte Quelle + evtl. Zitate daraus +/- Kommentare ==
zotero-citations  are                     citations                       + evtl. citation           + evtl. citation      +/- annotation ==

zotero-citations können mittels einem zotero-Plugin (zotmoov (2025-09-22)) nach obsidian_zotero exportiert werden.

>san(fn)< wandelt eine zotero -> obsidian_zotero *.md Note mit Annotations (Zitat + Kommentar)
in mehrere 'atomic' obsidian_zotero *.md Notes um, wobei jede der resultierenden 'atomic' obsidian_zotero *.md Notes
jeweils ein Zitat +- Kommentar enthält. Dazu kommen jeweils die Tags der ursprünglichen gesamt Note, ergänzt
um tags, die bei dem jeweiligen spezifischen Zitat angefügt wurden.

Die Ursprungs- 'gesamt' obsidian_zotero-s_content mit allen Einzelzitaten hat folgende Struktur:
- als Filenamen den Zitationsschlüssel (den zotero vergeben hat);
- als File-Inhalt:
    - den üblichen obsidian_zotero header (ua mit obsidian_zotero-frontmatter)
    - eine Präamble mit:
        %% begin summary %%
        ### Index
        ### Connections
        ## Fazit / Diskussion / Fragen    # Überschriften für Index, COnnections, Fazit ...
        tags: #tag_1 #tag_2 #etc          # tags, die für die gesamte obsidian_zotero Note gelten;
    - gefolgt von weiterem Text (>s_content<), der Form:
        %% begin annotations %%
        >s_content<
        %% end annotations %%

- >s_content< wiederum besteht aus Textblöcken, den Annotationen (Zitat +- Kommentar +- tags), jeweils der Form:

    %% Annotation_24Y6D63Q: Begin %%

    ###### 24Y6D63Q
    ## These_24Y6D63Q
    lorem ipsum ... [@bleasePaternalismus2016] [(p. 29)](zotero://open-pdf/library/items/4TCCEDY7?page=29&annotation=24Y6D63Q)
    %% Annotation_24Y6D63Q: annotatedText %%

    ### Kommentar
    lorem ipsum etc ...

    ### Tags
    tag_1 tag_2 tag_3 tag_4 tag_5 ...

    %% Annotation_24Y6D63Q: End %%

    wobei >24Y6D63Q< eine Signatur/Hash ist, die von zotero vergeben wurde: sie ist spezifisch für jeden Textblock
    und kennzeichnet inhaltlich genau eine Annotation, dh ein Zitat (+- Kommentar) aus der Quelle.

- Am Fileende noch das Importdatum:
    %% Import Date: 2025-05-18T00:28:06.405+02:00 %%

Insgesamt also:
    obsidian_zotero header (lesbar mit dem module frontmatter)

    %% begin annotations %%

        %% Annotation_Hash-01: Begin %%
        ###### Hash-01
        ## These_Hash-01
        lorem ipsum ...
        %% Annotation_Hash-01: annotatedText %%
        ### Kommentar
        ... dolor sit amet, ...
        ### Tags
        ... #tag_1 #tag_2 #tag_3 #etc
        %% Annotation_Hash-01: End %%

        %% Annotation_Hash-02: Begin %%
        ###### Hash-02
        ## These_Hash-02
        lorem ipsum ...
        %% Annotation_Hash-02: annotatedText %%
        ### Kommentar
        ... dolor sit amet, ...
        ### Tags
        ... #tag_1 #tag_2 #tag_3 #etc
        %% Annotation_Hash-02: End %%

        %% Annotation_Hash-03: Begin %%
        ###### Hash-03
        ## These_Hash-03
        lorem ipsum ...
        %% Annotation_Hash-03: annotatedText %%
        ### Kommentar
        ... dolor sit amet, ...
        ### Tags
        ... #tag_1 #tag_2 #tag_3 #etc
        %% Annotation_Hash-03: End %%

        ...

    %% end annotations %%
    %% Import Date: 2025-05-18T00:28:06.405+02:00 %%

>split_note_source_in_atomic_notes()< zerlegt nun die Ursprungs-obsidian_zotero s_content in kleinere obsidian_zotero-notes, wobei jede
genau eine Annotation (= Zitat + Kommentar) enthält, ergänzt um die tags der Ursprungs- Note.


Sonderfälle
===========

1. In zotero wird eine bestehende Zitation modifiziert und soll nun modifiziert ein zweites mal nach obsidian
importiert werden. Eine obsidian_zotero s_content ist also in diesem Fall schon vorhanden und wurde evtl. schon in
obsidian bearbeitet, evtl sogar schon in atomare notes zerlegt. Dh die Kommentare wurden evtl in obsidian modifiziert.
AUf jeden Fall sollen diese Modifikationen erhalten bleiben (und nicht überschrieben), wenn in zotero weitere Zitate
angefügt werden und die s_content ein weiteres mal nach obsidian importiert wird.
Das nunjucks-Template sorgt nun dafür, dass an die schon vorhandene obsidian_zotero s_content nur neue Zitate (annotations)
angefügt werden und bestehende annotations nicht verändert werden. (HOFFENTLICH!).

"""

def b_check_path_exists(l_path: list[Path]):
    for p_fn in l_path:
        if not p_fn.exists():
            msg = f"{p_fn =} does not exist => exit()."
            messagebox.showinfo(f"{os.path.basename(p_fn) =}", msg)
            exit()
    return


def b_san_nunjucks_version_exists(p_fn: str):
    if not get_value_from_dict_of_path(p_fn_note_source, "['san']['nunjucks_template']['version']"):
        msg = f"{p_fn =} not imported by nunjucks-template? => exit()."
        messagebox.showinfo(f"{os.path.basename(p_fn) =}", msg)
        return False
    else:
        return True


if __name__ == '__main__':
    # sys.argv[1] == >note.md< to be splitted.
    print()
    if len(sys.argv) > 1:
        fn_note_source = sys.argv[1]
        print(f"Received s_content: {fn_note_source}")
    else:  # Test
        fn_note_source = "bismarkLegal2012.md"
        print(f"No >note.md< name provided, take >{fn_note_source}<")

    p_fn_note_source: Path = Path(os.path.join(path_in, fn_note_source))
    print(f"Full path of >note.md< to read: {p_fn_note_source = }\n")

    cnt_notes_written = 0
    b_check_path_exists(l_path = [path_in, p_fn_note_source])
    if not b_san_nunjucks_version_exists(p_fn_note_source): exit()

    cnt_notes_written = split_note_source_in_atomic_notes(p_fn_note_source)

    if cnt_notes_written:
        backup_note_source_with_timestamp(p_fn_note_source)
        # backup_note_source(p_fn_note_source)

# ToDo:
#  zotero: There duplicates in the pdf folder. How can I get rid of them, without damaging the database?
#  * https://info.library.okstate.edu/zotero/storage

# ToDo:
#  >san.py< & >san.nunjucks< into
#   - one common directory and
#   - one common git repository (local and github).

# ToDo:
#  >san.py<  in *.exe verwandeln
#       >_ pip install pyinstaller
#       >_
#       >_ pyinstaller --onefile -w 'san.py'

# nb:
#  Obsidian community plugin: 'Shell commands' calls >san.exe< via shortcut
#    https://github.com/Taitava/obsidian-shellcommands
#    .
#    ctrl-P > Shell commands: Execute Split Into Annotation Notes (SAN)
#    >_Shell commands: (insert:)
#      "C:\Users\rh\Meine Ablage\obsidian_rh_GoogleDrive\zz_Templates_Scripts\Nunjucks_Templates\san.exe" "{{file_path:absolute}}"
#         /* Do not forget the quotation marks! */
#         /* with:  "{{file_path:absolute}}"  ==   "Gives the current file name with file extension" */
#      Output: Outputchannel for stdout: Notification balloon
#      Output: Outputchannel for stderr: Error balloon


