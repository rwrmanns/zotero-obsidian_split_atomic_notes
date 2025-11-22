import os
import re
import io
import configparser
import frontmatter
import random
import string

def load_config(ini_path):
    config = configparser.ConfigParser()
    config.read(ini_path)

    p_root = config['DEFAULT']['p_root']
    ext = config['DEFAULT']['ext']

    rgx_QA_exclude = re.compile(config['DEFAULT']['rgx_QA_exclude'], re.MULTILINE | re.DOTALL)
    rgx_QA_pattern = re.compile(config['DEFAULT']['rgx_QA_pattern'], re.MULTILINE | re.DOTALL)
    rgx_QA_hash = re.compile(config['DEFAULT']['rgx_QA_hash'])
    rgx_QA_DECK = re.compile(config['DEFAULT']['rgx_QA_DECK'], re.MULTILINE | re.DOTALL)

    return p_root, ext, rgx_QA_exclude, rgx_QA_pattern, rgx_QA_hash, rgx_QA_DECK

def generate_random_hash(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def find_files_with_extension(root, extension):
    matches = []
    for current_dir, _, filenames in os.walk(root):
        for fname in filenames:
            if fname.endswith(extension):
                matches.append(os.path.join(current_dir, fname))
    return matches

def get_l_s_QA_deck(content, rgx_QA_DECK, fixed_QA_prefix):
    deck_matches = rgx_QA_DECK.findall(content)
    l_s_QA_deck = [m[len(fixed_QA_prefix):] if m.startswith(fixed_QA_prefix) else m for m in deck_matches]
    return l_s_QA_deck

def process_files(file_paths, rgx_QA_exclude, rgx_QA_pattern, rgx_QA_hash, rgx_QA_DECK):
    result = []
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
        l_s_QA_deck = get_l_s_QA_deck(content, rgx_QA_DECK, fixed_QA_prefix)

        metadata = post.metadata
        zotero_hash = None
        if 'san' in metadata and isinstance(metadata['san'], dict):
            candidate = metadata['san'].get('zotero_hash')
            if candidate and rgx_QA_hash.fullmatch(candidate):
                zotero_hash = candidate

        if not zotero_hash:
            zotero_hash = generate_random_hash()
            if 'san' not in metadata or not isinstance(metadata['san'], dict):
                metadata['san'] = {}
            metadata['san']['zotero_hash'] = zotero_hash
            post.metadata = metadata
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(frontmatter.dumps(post))

        raw_matches = rgx_QA_pattern.findall(content)
        if raw_matches and isinstance(raw_matches[0], tuple):
            target_matches = [''.join(m) for m in raw_matches]
        else:
            target_matches = raw_matches

        modified_content = content
        multiple_matches = len(target_matches) > 1

        # Build a list of all existing hashes in content
        l_QA_hash = rgx_QA_hash.findall(content)

        for idx, match in enumerate(target_matches, start=1):
            if not rgx_QA_hash.search(match):
                escaped_match = re.escape(match)

                if multiple_matches:
                    candidate_idx = idx

                    # Test uniqueness without parentheses first
                    insert_str_no_paren = f'{zotero_hash}_{candidate_idx}'
                    while insert_str_no_paren in l_QA_hash:
                        candidate_idx += 1
                        insert_str_no_paren = f'{zotero_hash}_{candidate_idx}'

                    # After uniqueness found without parentheses, add parentheses
                    insert_str = f'({insert_str_no_paren})\n'
                else:
                    insert_str = f'({zotero_hash})\n'

                modified_content = re.sub(
                    rf'({escaped_match})',
                    rf'\1{insert_str}',
                    modified_content,
                    count=1
                )
                target_matches[idx-1] = match + insert_str

        new_filename = '_NEW_' + os.path.basename(file_path)
        with open(new_filename, 'w', encoding='utf-8') as f_new:
            fm_text = frontmatter.dumps(post)
            split_index = fm_text.find('---', 3)
            if split_index == -1:
                f_new.write(fm_text)
            else:
                frontmatter_header = fm_text[:split_index+3]
                f_new.write(frontmatter_header + '\n' + modified_content)

        qa_match = rgx_QA_pattern.search(content)

        entry = {
            'path': file_path,
            'target': target_matches if target_matches else None,
            'hash': zotero_hash,
            'qa': qa_match.group(0) if qa_match else None,
            'l_s_QA_deck': l_s_QA_deck,
        }
        result.append(entry)
    return result

def main():
    ini_path = 'tac.ini'
    p_root, ext, rgx_QA_exclude, rgx_QA_pattern, rgx_QA_hash, rgx_QA_DECK = load_config(ini_path)

    all_files = find_files_with_extension(p_root, ext)
    dts = process_files(all_files, rgx_QA_exclude, rgx_QA_pattern, rgx_QA_hash, rgx_QA_DECK)

    for entry in dts:
        print(entry)

if __name__ == "__main__":
    main()
