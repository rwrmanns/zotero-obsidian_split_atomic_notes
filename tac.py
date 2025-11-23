import os
import re
import io
import configparser
import frontmatter
import random
import string

fn_prefix = '_NEW_'

def load_config(ini_path):
    config = configparser.ConfigParser()
    config.read(ini_path)

    p_root = config['DEFAULT']['p_root']
    ext = config['DEFAULT']['ext']
    p_QA = config['DEFAULT']['p_QA']

    rgx_QA_exclude = re.compile(config['DEFAULT']['rgx_QA_exclude'], re.MULTILINE | re.DOTALL)
    rgx_QA_pattern = re.compile(config['DEFAULT']['rgx_QA_pattern'], re.MULTILINE | re.DOTALL)
    rgx_QA_hash = re.compile(config['DEFAULT']['rgx_QA_hash'])
    rgx_QA_DECK = re.compile(config['DEFAULT']['rgx_QA_DECK'], re.MULTILINE | re.DOTALL)

    return p_root, ext, p_QA, rgx_QA_exclude, rgx_QA_pattern, rgx_QA_hash, rgx_QA_DECK


def generate_random_hash(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))


def find_files_with_extension(root, extension):
    matches = []
    for current_dir, _, filenames in os.walk(root):
        for fname in filenames:
            if fname.endswith(extension):
                matches.append(os.path.normpath(os.path.join(current_dir, fname)))
    return matches


def get_l_s_QA_deck(content, rgx_QA_DECK, fixed_QA_prefix):
    deck_matches = rgx_QA_DECK.findall(content)
    lo_QA_deck = [m[len(fixed_QA_prefix):] if m.startswith(fixed_QA_prefix) else m for m in deck_matches]
    return lo_QA_deck


def files_are_identical(path1, content2):
    if not os.path.isfile(path1):
        return False
    with open(path1, 'r', encoding='utf-8') as f1:
        content1 = f1.read()
    return content1 == content2


def get_lo_qa_entry(file_paths, rgx_QA_exclude, rgx_QA_pattern, rgx_QA_hash, rgx_QA_DECK):
    lo_qa_entry = []
    for file_path in file_paths:
        try:
            post = frontmatter.load(file_path)
            content_io = io.StringIO(post.content)
            content = content_io.read()
        except Exception as e:
            print(f"Warning: Could not load frontmatter from {file_path}: {e}")
            continue

        if rgx_QA_exclude.search(content):
            continue

        if not rgx_QA_pattern.search(content):
            continue

        fixed_QA_prefix = "#QA_DECK_"
        lo_QA_deck = get_l_s_QA_deck(content, rgx_QA_DECK, fixed_QA_prefix)

        metadata = post.metadata
        QA_hash = None
        if 'san' in metadata and isinstance(metadata['san'], dict):
            candidate = metadata['san'].get('zotero_hash')
            if candidate and rgx_QA_hash.fullmatch(candidate):
                QA_hash = candidate

        if not QA_hash:
            QA_hash = generate_random_hash()
            if 'san' not in metadata or not isinstance(metadata['san'], dict):
                metadata['san'] = {}
            metadata['san']['zotero_hash'] = QA_hash
            post.metadata = metadata
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(frontmatter.dumps(post))

        raw_matches = rgx_QA_pattern.findall(content)
        if raw_matches and isinstance(raw_matches[0], tuple):
            l_s_qa = [''.join(m) for m in raw_matches]
        else:
            l_s_qa = raw_matches

        modified_content = content
        multiple_matches = len(l_s_qa) > 1

        lo_all_QA_hashes = rgx_QA_hash.findall(content)
        lo_qa_hash = [QA_hash] * len(l_s_qa)

        for idx, match in enumerate(l_s_qa, start=1):
            QA_hash_idx = ''
            if not rgx_QA_hash.search(match):
                escaped_match = re.escape(match)
                if not escaped_match.endswith('\n'):
                    escaped_match += '\n'

                if multiple_matches:
                    candidate_idx = idx
                    QA_hash_idx = f'{QA_hash}_{candidate_idx}'
                    while QA_hash_idx in lo_all_QA_hashes:
                        candidate_idx += 1
                        QA_hash_idx = f'{QA_hash}_{candidate_idx}'

                    insert_str = f'({QA_hash_idx})\n'
                else:
                    insert_str = f'({QA_hash})\n'

                modified_content = re.sub(
                    rf'({escaped_match})',
                    rf'\1{insert_str}',
                    modified_content,
                    count=1
                )
                l_s_qa[idx-1] = l_s_qa[idx-1] + '\n' + insert_str
                lo_qa_hash[idx-1] = QA_hash

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
            if files_are_identical(new_file_path, full_new_content):
                print(f"File identical, skipping overwrite: {new_file_path}")
            else:
                with open(new_file_path, 'w', encoding='utf-8') as f_new:
                    f_new.write(full_new_content)
                print(f"File updated: {new_file_path}")
        else:
            with open(new_file_path, 'w', encoding='utf-8') as f_new:
                f_new.write(full_new_content)
            print(f"File written: {new_file_path}")

        for s_QA in l_s_qa:
            for QA_deck in lo_QA_deck:
                match = re.search(rgx_QA_hash, s_QA)
                QA_hash = match.group(0) if match else ''
                qa_entry = {
                    'QA_deck': QA_deck,
                    's_QA': s_QA,
                    'QA_hash': QA_hash,
                    'path': file_path,
                }
                lo_qa_entry.append(qa_entry)

    return lo_qa_entry


def get_lo_qa_card(p_QA):
    prefix = 'TARGET DECK: '
    lo_p_fn_qa = []
    lo_qa_card = []

    for root, _, files in os.walk(p_QA):
        for fname in files:
            if fname.endswith('.md'):
                path_normalized = os.path.normpath(os.path.join(root, fname))
                lo_p_fn_qa.append(path_normalized)

    chunk_pattern = re.compile(
        r'((?:[^\n][\n]?)+) #flashcard ?\n*((?:\n(?:^.{1,3}$|^.{4}(?<!<!--).*))+)<' ,
        re.MULTILINE | re.VERBOSE
    )

    for p_fn_qa in lo_p_fn_qa:
        with open(p_fn_qa, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        if not lines:
            continue

        first_line = lines[0].strip()
        if not first_line.startswith(prefix):
            continue

        s_deck = first_line[len(prefix):]

        content = ''.join(lines)

        lo_s_qa = [m.group(0) for m in chunk_pattern.finditer(content)]

        for s_QA in lo_s_qa:
            if '#flashcard' in s_QA:
                lo_qa_card.append({
                    'QA_deck': s_deck,
                    's_QA': s_QA,
                    'file_path': p_fn_qa,
                })

    return lo_qa_card


def main():
    ini_path = 'tac.ini'
    p_root, ext, p_QA, rgx_QA_exclude, rgx_QA_pattern, rgx_QA_hash, rgx_QA_DECK = load_config(ini_path)

    all_files = find_files_with_extension(p_root, ext)
    lo_qa_entry = get_lo_qa_entry(all_files, rgx_QA_exclude, rgx_QA_pattern, rgx_QA_hash, rgx_QA_DECK)

    lo_qa_card = get_lo_qa_card(p_QA)

    for entry in lo_qa_entry:
        print(entry)

    for qa_card in lo_qa_card:
        print(qa_card)


if __name__ == "__main__":
    main()
