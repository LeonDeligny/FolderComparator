import os
import re
import fnmatch

def is_excluded(compiled_file_patterns_global, compiled_dir_patterns_global, compiled_root_specific_file_patterns_global, compiled_root_specific_dir_patterns_global, debug_exclude, debug_target, relative_path, is_dir_item, current_scan_folder_basename=None):
    """
    Checks if an item (file or directory) should be excluded based on compiled patterns.
    `relative_path` should be relative to the root of the scan (e.g., 'sub_dir/file.txt').
    `current_scan_folder_basename` is the basename of the current scan root (e.g., 'toto' for /home/user/toto).
    """

    # Normalize item_path for consistent matching (e.g., replace '\' with '/')
    normalized_item_path = relative_path.replace(os.sep, '/')

    # Activate verbose debug only if debug_exclude is True and either
    # debug_target is empty (debug all) or the path contains a target pattern.
    enable_verbose_debug = debug_exclude and \
                           (not debug_target or any(target_str in normalized_item_path for target_str in debug_target))

    if enable_verbose_debug:
        print(f"\n--- DEBUG EXCLUDE ---")
        print(f"  Checking path: '{relative_path}' (Is Dir: {is_dir_item})")
        print(f"  Normalized path for regex: '{normalized_item_path}'")
        print(f"  Root Basename Context: '{current_scan_folder_basename}'")

    # 1. Check root-specific patterns first (e.g., 'toto/activate*')
    if current_scan_folder_basename: # Only proceed if root context is available
        if is_dir_item:
            for root_name, compiled_regex, original_glob in compiled_root_specific_dir_patterns_global:
                if root_name == current_scan_folder_basename:
                    # Match against the remainder of the path, relative to the root_name
                    # e.g., for 'toto/activate*', normalized_item_path='activate-smr2.csh' or 'subdir/config/'
                    if compiled_regex.match(normalized_item_path):
                        if enable_verbose_debug:
                            print(f"  -> EXCLUDED by ROOT_SPECIFIC_DIR pattern '{original_glob}' (regex '{compiled_regex.pattern}') on '{normalized_item_path}' for root '{current_scan_folder_basename}'")
                        return True, original_glob
        else: # is_file_item
            for root_name, compiled_regex, original_glob in compiled_root_specific_file_patterns_global:
                if root_name == current_scan_folder_basename:
                    # Match against the remainder of the path, relative to the root_name
                    if compiled_regex.match(normalized_item_path):
                        if enable_verbose_debug:
                            print(f"  -> EXCLUDED by ROOT_SPECIFIC_FILE pattern '{original_glob}' (regex '{compiled_regex.pattern}') on '{normalized_item_path}' for root '{current_scan_folder_basename}'")
                        return True, original_glob

    # 2. Check general patterns (starting with `**/` or general `filename`, `dir/`)
    if is_dir_item:
        for original_glob, compiled_regex in compiled_dir_patterns_global:
            if enable_verbose_debug:
                print(f"      ---> DEBUG: Checking against general DIR pattern: '{original_glob}'")
                print(f"      ---> DEBUG:   Compiled REGEX: '{compiled_regex.pattern}'")
                print(f"      ---> DEBUG:   Path to check: '{normalized_item_path}'")
                match_obj = compiled_regex.match(normalized_item_path) # Use match() for start of string
                print(f"      ---> DEBUG:   re.match result: {match_obj}")

            if compiled_regex.match(normalized_item_path):
                if enable_verbose_debug:
                    print(f"  -> EXCLUDED by general DIR pattern '{original_glob}' (regex '{compiled_regex.pattern}') on '{normalized_item_path}'")
                return True, original_glob
    else: # is_file_item
        for original_glob, compiled_regex in compiled_file_patterns_global:
            if enable_verbose_debug:
                print(f"      ---> DEBUG: Checking against general FILE pattern: '{original_glob}'")
                print(f"      ---> DEBUG:   Compiled REGEX: '{compiled_regex.pattern}'")
                print(f"      ---> DEBUG:   Path to check: '{normalized_item_path}'")
                match_obj = compiled_regex.match(normalized_item_path) # Use match() for start of string
                print(f"      ---> DEBUG:   re.match result: {match_obj}")

            if compiled_regex.match(normalized_item_path):
                if enable_verbose_debug:
                    print(f"  -> EXCLUDED by general FILE pattern '{original_glob}' (regex '{compiled_regex.pattern}') on '{normalized_item_path}'")
                return True, original_glob

    if enable_verbose_debug:
        print(f"  -> NOT EXCLUDED")
    return False, None


def compile_exclusion_patterns(debug_exclude, debug_target, patterns_list):
    """
    Compile glob-style exclusion patterns into regular expressions.
    Separates patterns into file and directory lists, and handles root-specific patterns.
    """
    # Reset for each call, if any
    compiled_file_patterns_global = []
    compiled_dir_patterns_global = []
    compiled_root_specific_file_patterns_global = [] 
    compiled_root_specific_dir_patterns_global = []  # Reset for each call, if any

    # Regex to detect root-specific patterns like "folder_name/file_or_pattern"
    # Captures "folder_name" in group 1 and "file_or_pattern" in group 2.
    # Ensures that there is at least one character in the remainder.
    root_specific_regex = re.compile(r'^(?P<root_name>[^/]+)/(?P<remainder>.+)$') # Changed `.*` to `.+`

    for original_glob in patterns_list:
        is_dir_pattern = original_glob.endswith('/')
        fnmatch_regex = fnmatch.translate(original_glob)

        # Check for root-specific pattern (e.g., toto/activate*)
        match_root_specific = root_specific_regex.match(original_glob)

        if original_glob.startswith('**/'):
            # Handle `**` patterns: make them match zero or more directories recursively.
            # Remove `(?s:` and `)\Z` from fnmatch.translate output to insert custom `(?:[^/]*/)*?`

            glob_after_wildcard = original_glob[3:] # removes `**` and the `/` if present

            # Translate only the part after `**`
            translated_suffix_inner = fnmatch.translate(glob_after_wildcard)
            # Remove `(?s:` and `)\Z` from this inner translation to make it flexible
            if translated_suffix_inner.startswith('(?s:') and translated_suffix_inner.endswith(')\\Z'):
                translated_suffix_inner = translated_suffix_inner[4:-3]

            # Construct the final regex: `^` (start) then `(?:[^/]*/)*?` (zero or more directories non-greedily)
            # then `translated_suffix_inner` and `\Z` (end)
            if is_dir_pattern:
                # For directories, ensure it matches the directory itself and anything inside it
                # Example: `**/dir/` -> matches `dir/` and `dir/file.txt`, `dir/subdir/`
                fnmatch_regex = r'(?s:(?:^|/)(?:[^/]*/)*?' + translated_suffix_inner + r'(?:.*)?)\Z'
                compiled_dir_patterns_global.append((original_glob, re.compile(fnmatch_regex)))
                if debug_exclude and any(p in original_glob for p in debug_target): # Adjusted filter check for compilation debug
                    print(f"DEBUG_REGEX_PROBLEM: (**/) DIR: '{original_glob}' -> Regex: '{fnmatch_regex}'")
            else: # ** pattern for files (e.g., **/.texlive*)
                # For files, match the filename directly anywhere.
                file_fnmatch_regex = r'(?s:(?:^|/)(?:[^/]*/)*?' + translated_suffix_inner + r')\Z'
                compiled_file_patterns_global.append((original_glob, re.compile(file_fnmatch_regex)))

                # For file patterns like `**/.texlive*`, they could also apply to directories like `.texlive2018/`
                # So, we also add a directory regex for them, similar to `**/dir/`
                dir_fnmatch_regex = r'(?s:(?:^|/)(?:[^/]*/)*?' + translated_suffix_inner + r'(?:.*)?)\Z'
                compiled_dir_patterns_global.append((original_glob, re.compile(dir_fnmatch_regex)))

                if debug_exclude and any(p in original_glob for p in debug_target): # Adjusted filter check for compilation debug
                    print(f"DEBUG_REGEX_PROBLEM: (**/) FILE/DIR: '{original_glob}' -> File Regex: '{file_fnmatch_regex}', Dir Regex: '{dir_fnmatch_regex}'")

        elif match_root_specific: #
            root_name = match_root_specific.group(1) # e.g., 'toto'
            remainder_glob = match_root_specific.group(2) # e.g., 'activate*' or '.config/'
            remainder_is_dir_pattern = remainder_glob.endswith('/')
            remainder_fnmatch_regex = fnmatch.translate(remainder_glob)

            # Remove (?s: and )\Z from the translated remainder for internal use
            if remainder_fnmatch_regex.startswith('(?s:') and remainder_fnmatch_regex.endswith(')\\Z'):
                remainder_fnmatch_regex_cleaned = remainder_fnmatch_regex[4:-3]
            else:
                remainder_fnmatch_regex_cleaned = remainder_fnmatch_regex

            # For directory remainders, ensure it matches the directory and anything inside it
            if remainder_is_dir_pattern:
                final_regex = r'(?s:' + remainder_fnmatch_regex_cleaned + r'(?:.*)?)\Z'
                compiled_root_specific_dir_patterns_global.append((root_name, re.compile(final_regex), original_glob))
                if debug_exclude and any(p in original_glob for p in debug_target): # Adjusted filter check for compilation debug
                     print(f"DEBUG_REGEX_PROBLEM: ROOT_SPECIFIC DIR: '{original_glob}' (root='{root_name}') -> Remainder Regex: '{final_regex}'")
            else: # File remainder
                final_regex = r'(?s:' + remainder_fnmatch_regex_cleaned + r')\Z'
                compiled_root_specific_file_patterns_global.append((root_name, re.compile(final_regex), original_glob))
                if debug_exclude and any(p in original_glob for p in debug_target): # Adjusted filter check for compilation debug
                    print(f"DEBUG_REGEX_PROBLEM: ROOT_SPECIFIC FILE: '{original_glob}' (root='{root_name}') -> Remainder Regex: '{final_regex}'")

        elif is_dir_pattern: # Normal directory pattern (e.g., my_dir/)
            # Ensure it matches the directory itself and anything inside it recursively.
            # If fnmatch.translate gives '(?s:dir/)\Z', we want '(?s:dir/(?:.*)?)\Z'
            # Check if fnmatch.translate already added recursive match for directories.
            if fnmatch_regex.endswith(')\\Z'):
                # Split at the last ')\Z' to insert '(?:.*)?' before it
                fnmatch_regex = fnmatch_regex.rsplit(')\\Z', 1)[0] + r'(?:.*)?)\Z'
            # If it doesn't end with ')\Z', it's already a simpler regex, just append `(?:.*)?`
            # (This else branch is less common for directory patterns from fnmatch.translate)
            else:
                fnmatch_regex = fnmatch_regex + r'(?:.*)?' # Fallback, should not happen often

            compiled_dir_patterns_global.append((original_glob, re.compile(fnmatch_regex)))
            if debug_exclude and any(p in original_glob for p in debug_target): # Adjusted filter check for compilation debug
                print(f"DEBUG_REGEX_PROBLEM: DIR (normal): '{original_glob}' -> Regex: '{fnmatch_regex}'")
        else: # Normal file pattern (e.g., my_file.txt)
            compiled_file_patterns_global.append((original_glob, re.compile(fnmatch_regex)))
            if debug_exclude and any(p in original_glob for p in debug_target): # Adjusted filter check for compilation debug
                print(f"DEBUG_REGEX_PROBLEM: FILE (normal): '{original_glob}' -> Regex: '{fnmatch_regex}'")

    return compiled_file_patterns_global, compiled_dir_patterns_global
