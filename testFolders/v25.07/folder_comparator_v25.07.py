import os
import sys
import hashlib
import argparse
import fnmatch
import re
import time
import datetime
import textwrap # For better help formatting
import math


# --- Script Description ---
#
SCRIPT_VERSION = "v25.07"
SCRIPT_DATE    = "14-July-2025"
#
# A. Gehri/Gemini
#
# This script compares two folders (source and target) to identify and report
# on items based on their existence, modification dates, and size.
#
# It provides a detailed report on the following exclusive categories:
#  1. Broken symbolic links found in the source folder.
#  2. Broken symbolic links found in the target folder.
#  3. Files existing only in the source folder.
#  4. Files existing only in the target folder.
#  5. Files existing in both source and target that are considered IDENTICAL.
#     - Identical means: (a) sizes are identical AND (b) timestamps are within
#       a user-defined time tolerance.
#     - An optional hash check (--hash-check) can be enabled for stricteri
#       identity verification, in which case files are identical ONLY if
#       their content hashes match (along with size).
#  6. Files existing in both source and target, which are DIFFERENT, andi
#     source is newer.
#  7. Files existing in both source and target, which are DIFFERENT, and
#     target is newer.
#  8. Files/Folders excluded based on --exclude patterns
#  9. Items that have different types (File/Folder) in Source an Target
# 10. Items for which an error has occurred during comparison
#
# The report includes the count and total size for each file category.
# Users can specify patterns to exclude certain files or folders from the
# comparison, either directly via command-line arguments or by providing a
# file containing the patterns.
#
# Usage examples:
# ---------------
# python3 folder_comparator.py --exclude "*.log", "toto/activate*", "temp_dir/" -- source_dir target_dir
# python3 folder_comparator.py --exclude-file my_exclusions.txt --time-tolerance 0.1 -hash-check md5 -- source_dir target_dir
#
# Note on timestamps (modification time):
# ---------------------------------------
# Sometimes, when manipulating files, the modification timestamp may be rounded
# to the nearest second, in which case the use of --time-tolerance 1 should
# indicate that such files should be treated as identical.
#
# Note on the logic for size calculation:
# ---------------------------------------
# For reporting and comparison purposes, item sizes are handled as follows:
#   - Regular Files: Their actual byte size is used.
#   - Directories: Have no meaningful "content size" in bytes.
#                  Their size is recorded as 'None' during scanning and
#                  displayed as 'None bytes' in the report.
#                  They are not included in total size sums.
#   - Symbolic Links: The size recorded is the actual size of the symlink
#                     entry itself (i.e., the byte length of the target
#                     path string it contains), not the size of its target.
#                     This size is a numerical value, displayed as 'XX bytes',
#                     and included in total size sums where applicable.
#   - Broken symlinks are reported separately and do not have a size
#     associated for comparison.
# This approach ensures clear distinction between actual file content size,
# the conceptual 'size' of directories, and the true footprint of symlinks.

#
# --- End of Script Description ---


# --- Constants for Comparison Outcomes and Report Categories ---
# These are the 10 definitive report categories
# The titles of the categories reported in the final report are defined in the print_report function
REPORT_BROKEN_SYMLINK_SOURCE = "Broken Symbolic Links found in Source."
REPORT_BROKEN_SYMLINK_TARGET = "Broken Symbolic Links found in Target."
REPORT_ONLY_IN_SOURCE = "Files existing ONLY in Source."
REPORT_ONLY_IN_TARGET = "Files existing ONLY in Target."
REPORT_IDENTICAL = "Files in Source AND Target that are IDENTICAL" # The detailed explanation will be built dynamically in print_report
REPORT_DIFFERENT_CONTENT_SOURCE_NEWER = "Files in Source AND Target that are DIFFERENT, and SOURCE is newer."
REPORT_DIFFERENT_CONTENT_TARGET_NEWER = "Files in Source AND Target that are DIFFERENT, and TARGET is newer."
REPORT_EXCLUDED = "Excluded Files/Folders (based on --exclude patterns)."
REPORT_DIFFERENT_TYPE = "Items with Different Type (File vs. Folder) found in both Source and Target."
REPORT_COMPARE_ERROR = "Comparison Errors."

# --- Global variables for optimization and debugging ---
compiled_file_patterns_global = []
compiled_dir_patterns_global = []
compiled_root_specific_file_patterns_global = []
compiled_root_specific_dir_patterns_global = []
patterns_compiled_flag = False
DEBUG_EXCLUDE_ENABLED = False
DEBUG_TARGET_PATTERNS = [] # Populated from args

# --- Gloabl variables related to the exclusions patterns
all_exclude_patterns = []
num_patterns_from_exclude_file = 0

# --- Global variables for cleaned paths (set in main)
source_folder_cleaned = ""
target_folder_cleaned = ""

# --- Core Utility Functions ---

def calculate_hash(file_path, hash_algorithm='md5', block_size=65536):
    """Calculates the hash of a file using the specified algorithm (md5 or sha256)."""
    if hash_algorithm == 'md5':
        hasher = hashlib.md5()
    elif hash_algorithm == 'sha256':
        hasher = hashlib.sha256()
    else:
        return None # Should not happen with argparse choices

    try:
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                hasher.update(block)
        return hasher.hexdigest()
    except Exception as e:
        return None # Indicate failure to calculate hash

def _glob_to_regex_core(glob_pattern_normalized):
    """
    Converts a normalized global pattern into a regular expression.
    Handles wildcards ‘*’, ‘**’, ‘?’, and escapes other special regex characters.
    Adds NO anchors (^, $, or /) - these are added by the calling function.
    If ‘**’ is present in the global pattern, ‘*’ will also match slashes.
    """
    regex_parts = []

    has_recursive_wildcard = '**' in glob_pattern_normalized

    parts = glob_pattern_normalized.split('**')

    for i, part_containing_slashes in enumerate(parts):
        if i > 0: # If this is not the first part, it was preceded by '**'
            regex_parts.append('.*') # '**' matches everything, including slashes

        # Process the current part, which might contain literal slashes
        # The key here is how we handle leading slashes in parts, and how * and ? behave.

        # Split by literal slashes *without escaping them here yet*
        segments = part_containing_slashes.split('/')

        for j, segment in enumerate(segments):
            if j > 0: # Add a literal slash if not the first segment in this part
                regex_parts.append('/')

            # Escape regex special characters in the segment
            escaped_segment = re.escape(segment)

            # Replace glob wildcards with regex equivalents based on `has_recursive_wildcard`
            if has_recursive_wildcard:
                escaped_segment = escaped_segment.replace(re.escape('*'), '.*')
                escaped_segment = escaped_segment.replace(re.escape('?'), '.')
            else:
                escaped_segment = escaped_segment.replace(re.escape('*'), '[^/]*')
                escaped_segment = escaped_segment.replace(re.escape('?'), '[^/]')

            regex_parts.append(escaped_segment)

    # Special handling for patterns starting with '/': anchor to start of path
    # But `_glob_to_regex_core` should not add anchors, so this is just a comment for caller.

    return "".join(regex_parts)

def compile_exclusion_patterns(patterns_list):
    """
    Compile glob-style exclusion patterns into regular expressions.
    Separates patterns into file and directory lists, and handles root-specific patterns.
    """
    global compiled_file_patterns_global, compiled_dir_patterns_global
    global compiled_root_specific_file_patterns_global, compiled_root_specific_dir_patterns_global
    global DEBUG_EXCLUDE_ENABLED, DEBUG_TARGET_PATTERNS

    compiled_file_patterns_global = []
    compiled_dir_patterns_global = []
    compiled_root_specific_file_patterns_global = [] # Reset for each call, if any
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
                if DEBUG_EXCLUDE_ENABLED and any(p in original_glob for p in DEBUG_TARGET_PATTERNS): # Adjusted filter check for compilation debug
                    print(f"DEBUG_REGEX_PROBLEM: (**/) DIR: '{original_glob}' -> Regex: '{fnmatch_regex}'")
            else: # ** pattern for files (e.g., **/.texlive*)
                # For files, match the filename directly anywhere.
                file_fnmatch_regex = r'(?s:(?:^|/)(?:[^/]*/)*?' + translated_suffix_inner + r')\Z'
                compiled_file_patterns_global.append((original_glob, re.compile(file_fnmatch_regex)))

                # For file patterns like `**/.texlive*`, they could also apply to directories like `.texlive2018/`
                # So, we also add a directory regex for them, similar to `**/dir/`
                dir_fnmatch_regex = r'(?s:(?:^|/)(?:[^/]*/)*?' + translated_suffix_inner + r'(?:.*)?)\Z'
                compiled_dir_patterns_global.append((original_glob, re.compile(dir_fnmatch_regex)))

                if DEBUG_EXCLUDE_ENABLED and any(p in original_glob for p in DEBUG_TARGET_PATTERNS): # Adjusted filter check for compilation debug
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
                if DEBUG_EXCLUDE_ENABLED and any(p in original_glob for p in DEBUG_TARGET_PATTERNS): # Adjusted filter check for compilation debug
                     print(f"DEBUG_REGEX_PROBLEM: ROOT_SPECIFIC DIR: '{original_glob}' (root='{root_name}') -> Remainder Regex: '{final_regex}'")
            else: # File remainder
                final_regex = r'(?s:' + remainder_fnmatch_regex_cleaned + r')\Z'
                compiled_root_specific_file_patterns_global.append((root_name, re.compile(final_regex), original_glob))
                if DEBUG_EXCLUDE_ENABLED and any(p in original_glob for p in DEBUG_TARGET_PATTERNS): # Adjusted filter check for compilation debug
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
            if DEBUG_EXCLUDE_ENABLED and any(p in original_glob for p in DEBUG_TARGET_PATTERNS): # Adjusted filter check for compilation debug
                print(f"DEBUG_REGEX_PROBLEM: DIR (normal): '{original_glob}' -> Regex: '{fnmatch_regex}'")
        else: # Normal file pattern (e.g., my_file.txt)
            compiled_file_patterns_global.append((original_glob, re.compile(fnmatch_regex)))
            if DEBUG_EXCLUDE_ENABLED and any(p in original_glob for p in DEBUG_TARGET_PATTERNS): # Adjusted filter check for compilation debug
                print(f"DEBUG_REGEX_PROBLEM: FILE (normal): '{original_glob}' -> Regex: '{fnmatch_regex}'")

    return compiled_file_patterns_global, compiled_dir_patterns_global

def is_excluded(relative_path, is_dir_item, current_scan_folder_basename=None):
    """
    Checks if an item (file or directory) should be excluded based on compiled patterns.
    `relative_path` should be relative to the root of the scan (e.g., 'sub_dir/file.txt').
    `current_scan_folder_basename` is the basename of the current scan root (e.g., 'toto' for /home/user/toto).
    """
    global compiled_file_patterns_global, compiled_dir_patterns_global
    global compiled_root_specific_file_patterns_global, compiled_root_specific_dir_patterns_global
    global DEBUG_EXCLUDE_ENABLED, DEBUG_TARGET_PATTERNS

    # Normalize item_path for consistent matching (e.g., replace '\' with '/')
    normalized_item_path = relative_path.replace(os.sep, '/')

    # Activate verbose debug only if DEBUG_EXCLUDE_ENABLED is True and either
    # DEBUG_TARGET_PATTERNS is empty (debug all) or the path contains a target pattern.
    enable_verbose_debug = DEBUG_EXCLUDE_ENABLED and \
                           (not DEBUG_TARGET_PATTERNS or any(target_str in normalized_item_path for target_str in DEBUG_TARGET_PATTERNS))

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

# --- Scanning and Comparison Logic ---

# Helper class to store scanned item details
class ScannedItem:
    def __init__(self, full_path, is_dir, size, mtime_ns, is_symlink, symlink_target=None):
        self.full_path = full_path
        self.is_dir = is_dir
        self.size = size
        self.mtime_ns = mtime_ns # Use nanoseconds for precision, convert to seconds when needed
        self.is_symlink = is_symlink
        self.symlink_target = symlink_target # Stores the target path if it's a symlink

def _scan_folder(root_path, comparison_results_dict, is_source_scan_flag, ignore_case):
    # This function now directly populates comparison_results_dict for all categories

    current_scan_folder_basename = os.path.basename(root_path)

    scanned_non_excluded_items = {}
    print(f"{'Scanning folder':<25} : {root_path} ...")

    for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
        # Determine relative path of current directory for exclusion checks
        current_relative_dir = os.path.relpath(dirpath, root_path)
        if current_relative_dir == ".": # Root directory itself
            current_relative_dir = "" 

        # Process directories first (dirnames is mutable, can be modified to prune walk)
        dirnames_to_process = list(dirnames) # Iterate over a copy
        for dirname in dirnames_to_process:
            full_path = os.path.join(dirpath, dirname)
            relative_path = os.path.join(current_relative_dir, dirname)
            relative_path_with_sep = relative_path + os.sep # For directory patterns and reporting
            is_excluded_flag = False
            matched_pattern = None # Initialize matched_pattern

            # --- Check for broken symlinks ---
            is_current_symlink = os.path.islink(full_path)
            if is_current_symlink:
                try:
                    # Does the symlink's target exist?
                    if not os.path.exists(os.path.realpath(full_path)):
                        # It's a broken symlink. Add it and remove from further processing.
                        if is_source_scan_flag:
                            comparison_results_dict[REPORT_BROKEN_SYMLINK_SOURCE].append(relative_path_with_sep)
                        else:
                            comparison_results_dict[REPORT_BROKEN_SYMLINK_TARGET].append(relative_path_with_sep)
                        if DEBUG_EXCLUDE_ENABLED:
                            print(f"DEBUG: Broken symlink (dir) detected in {current_scan_folder_basename}: {relative_path_with_sep}")
                        dirnames.remove(dirname) # Prune this directory from further walk if it's a symlink
                        continue # Skip further processing for this broken symlink
                except OSError as e:
                    # Error accessing the symlink itself or its target path during realpath check.
                    # Treat as a broken symlink (as we can't verify its target due to error) and also log as error for visibility.
                    if is_source_scan_flag:
                        comparison_results_dict[REPORT_BROKEN_SYMLINK_SOURCE].append(f"{relative_path_with_sep} (realpath error: {e})")
                    else:
                        comparison_results_dict[REPORT_BROKEN_SYMLINK_TARGET].append(f"{relative_path_with_sep} (realpath error: {e})")
                    if DEBUG_EXCLUDE_ENABLED:
                        print(f"DEBUG: Broken symlink (dir, realpath error) detected in {current_scan_folder_basename}: {relative_path_with_sep} (realpath error: {e})")
                    comparison_results_dict[REPORT_COMPARE_ERROR].append(f"{relative_path_with_sep} (symlink realpath error: {e})")
                    dirnames.remove(dirname) # Prune this directory from further walk
                    continue

            # --- Check for exclusion ---
            comparison_results_dict[REPORT_EXCLUDED].append((relative_path_with_sep, matched_pattern, current_scan_folder_basename, is_source_scan_flag, True, None)) # is_dir=True, size=None
            if is_excluded_flag:
                if DEBUG_EXCLUDE_ENABLED:
                    print(f"DEBUG EXCLUDE (DIR): {current_scan_folder_basename} - '{relative_path_with_sep}' matched by '{matched_pattern}'")
                comparison_results_dict[REPORT_EXCLUDED].append((relative_path_with_sep, matched_pattern, current_scan_folder_basename, is_source_scan_flag))
                dirnames.remove(dirname) # Prune this directory from further walk
                continue # Skip further processing for this excluded directory

            # If not excluded and not a broken symlink, add to scanned items for later comparison
            # Directories don't have size or mtime for comparison purposes
            try:
                dir_stat = os.lstat(full_path) if is_current_symlink else os.stat(full_path)
                key_path = relative_path.lower() if ignore_case else relative_path
                scanned_non_excluded_items[key_path] = ScannedItem(
                    full_path=full_path,
                    is_dir=True,
                    size=None, # Size for directories is still None as it's not directly comparable
                    mtime_ns=dir_stat.st_mtime_ns, # Capture mtime_ns for directories
                    is_symlink=is_current_symlink,
                    symlink_target=os.path.realpath(full_path) if is_current_symlink else None
                )
            except OSError as e:
                # Log an error if we can't stat the directory, but still allow scan to continue
                comparison_results_dict[REPORT_COMPARE_ERROR].append(f"{relative_path_with_sep} (directory scanning error: {e})")
                continue # Skip this directory if we can't get its stats

        # Process files
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            relative_path = os.path.join(current_relative_dir, filename)

            is_excluded_flag = False
            matched_pattern = None # Initialize matched_pattern

            # --- Check for broken symlinks ---
            is_current_symlink = os.path.islink(full_path)
            if is_current_symlink:
                try:
                    if not os.path.exists(os.path.realpath(full_path)):
                        if is_source_scan_flag:
                            comparison_results_dict[REPORT_BROKEN_SYMLINK_SOURCE].append(relative_path)
                        else:
                            comparison_results_dict[REPORT_BROKEN_SYMLINK_TARGET].append(relative_path)
                        if DEBUG_EXCLUDE_ENABLED:
                            print(f"DEBUG: Broken symlink (file) detected in {current_scan_folder_basename}: {relative_path}")
                        continue # Skip further processing
                except OSError as e:
                    if is_source_scan_flag:
                        comparison_results_dict[REPORT_BROKEN_SYMLINK_SOURCE].append(f"{relative_path} (realpath error: {e})")
                    else:
                        comparison_results_dict[REPORT_BROKEN_SYMLINK_TARGET].append(f"{relative_path} (realpath error: {e})")
                    if DEBUG_EXCLUDE_ENABLED:
                        print(f"DEBUG: Broken symlink (file, realpath error) detected in {current_scan_folder_basename}: {relative_path} (realpath error: {e})")
                    comparison_results_dict[REPORT_COMPARE_ERROR].append(f"{relative_path} (symlink realpath error: {e})")
                    continue

            # --- Check for exclusion ---
            is_excluded_flag, matched_pattern = is_excluded(relative_path, False, current_scan_folder_basename) # Re-assign if excluded
            if is_excluded_flag:
                if DEBUG_EXCLUDE_ENABLED:
                    print(f"DEBUG EXCLUDE (FILE): {current_scan_folder_basename} - '{relative_path}' matched by '{matched_pattern}'")
                comparison_results_dict[REPORT_EXCLUDED].append((relative_path, matched_pattern, current_scan_folder_basename, is_source_scan_flag, False, file_stat.st_size)) # is_dir=False, size=file_stat.st_size
                continue # Skip further processing

            # If not excluded and not a broken symlink, add to scanned items
            try:
                # For symlinks, use os.lstat to get information about the link itself.
                # For regular files, use os.stat.
                file_stat = os.lstat(full_path) if is_current_symlink else os.stat(full_path)

                key_path = relative_path.lower() if ignore_case else relative_path
                scanned_non_excluded_items[key_path] = ScannedItem(
                    full_path=full_path,
                    is_dir=False,
                    size=file_stat.st_size,
                    mtime_ns=file_stat.st_mtime_ns,
                    is_symlink=is_current_symlink,
                    symlink_target=os.path.realpath(full_path) if is_current_symlink else None
                )
            except OSError as e:
                # This is a file that is not a broken symlink or excluded, but we can't stat it.
                # This is a valid comparison error.
                comparison_results_dict[REPORT_COMPARE_ERROR].append(f"{relative_path} (scanning error: {e})")
    
    print("Finished scanning folders\n")

    return scanned_non_excluded_items

def compare_scanned_items(source_items_dict, target_items_dict, comparison_results_dict, time_tolerance, hash_check):
    """
    Compares the pre-scanned non-excluded items from source and target folders
    and populates the comparison_results_dict according to the 10 categories.
    """

    print("Comparing items ...")

    all_relative_paths = sorted(list(source_items_dict.keys() | target_items_dict.keys()))

    for relative_path in all_relative_paths:
        source_item = source_items_dict.get(relative_path)
        target_item = target_items_dict.get(relative_path)

        # 1. Handle Only in Source / Only in Target
        if source_item and not target_item:
            # Store path and source size for files/folders only in source
            if source_item.is_dir:
                comparison_results_dict[REPORT_ONLY_IN_SOURCE].append((relative_path + os.sep, source_item.size))
            else:
                comparison_results_dict[REPORT_ONLY_IN_SOURCE].append((relative_path, source_item.size))
            continue
        elif target_item and not source_item:
            # Store path and target size for files/folders only in target
            if target_item.is_dir:
                comparison_results_dict[REPORT_ONLY_IN_TARGET].append((relative_path + os.sep, target_item.size))
            else:
                comparison_results_dict[REPORT_ONLY_IN_TARGET].append((relative_path, target_item.size))
            continue
        
        # At this point, both source_item and target_item exist and are not broken symlinks (handled during scan).

        # 2. Handle Different Type (File vs. Folder)
        if source_item.is_dir != target_item.is_dir:
            comparison_results_dict[REPORT_DIFFERENT_TYPE].append((relative_path, f"{'Directory' if source_item.is_dir else 'File'} vs {'Directory' if target_item.is_dir else 'File'}"))
            continue
        
        # At this point, both are either files or both are directories.

        # 3. If both are directories, they are identical (content is recursive, not simple size/mtime)
        if source_item.is_dir and target_item.is_dir: # Both are directories
            # Compare mtime for directories as well for consistent reporting
            # Ensure mtime_ns is not None before comparison; if None, treat as different.
            if source_item.mtime_ns is None or target_item.mtime_ns is None:
                # If mtime_ns is missing for a directory, consider it different for now.
                # This might indicate a scanning issue or an intentional lack of mtime for directories.
               comparison_results_dict[REPORT_COMPARE_ERROR].append((relative_path + os.sep, "Directory mtime information missing"))
               continue # Move to next item

            mtime1_s = source_item.mtime_ns / 1_000_000_000
            mtime2_s = target_item.mtime_ns / 1_000_000_000

            if abs(mtime1_s - mtime2_s) <= time_tolerance:
                # mtime within tolerance, consider directories identical
                comparison_results_dict[REPORT_IDENTICAL].append((relative_path + os.sep, None))
            elif source_item.mtime_ns > target_item.mtime_ns:
                # Source directory is newer (mtime outside tolerance)
                comparison_results_dict[REPORT_DIFFERENT_CONTENT_SOURCE_NEWER].append((relative_path + os.sep, None, None))
            else:
                # Target directory is newer (mtime outside tolerance)
                comparison_results_dict[REPORT_DIFFERENT_CONTENT_TARGET_NEWER].append((relative_path + os.sep, None, None))
            continue
        
        # At this point, both are files. Perform file content comparison.

        try:
            # 4. Compare Files - Size
            if source_item.size is None or target_item.size is None:
                # This case should ideally not happen if _scan_folder populated size correctly for files.
                # It might happen if os.stat failed, which would be logged as a scanning error.
                # However, for robustness, if it does, log a comparison error.
                comparison_results_dict[REPORT_COMPARE_ERROR].append(f"{relative_path} (file size information missing during comparison)")
                continue
            
            if source_item.size != target_item.size:
                # Sizes differ, it's a different file. Determine newer based on mtime.
                if source_item.mtime_ns > target_item.mtime_ns:
                    # Store path, source size, and target size for source newer files
                    comparison_results_dict[REPORT_DIFFERENT_CONTENT_SOURCE_NEWER].append((relative_path, source_item.size, target_item.size))
                else:
                    # Store path, source size, and target size for target newer files
                    comparison_results_dict[REPORT_DIFFERENT_CONTENT_TARGET_NEWER].append((relative_path, source_item.size, target_item.size))
                continue

            # Sizes are identical. Proceed to mtime/hash check.
            mtime1_s = source_item.mtime_ns / 1_000_000_000
            mtime2_s = target_item.mtime_ns / 1_000_000_000

            if abs(mtime1_s - mtime2_s) <= time_tolerance:
                # mtime within tolerance
                if hash_check:
                    # Perform hash check if specified
                    hash1 = calculate_hash(source_item.full_path, hash_check)
                    hash2 = calculate_hash(target_item.full_path, hash_check)

                    if hash1 is None or hash2 is None:
                        comparison_results_dict[REPORT_COMPARE_ERROR].append(f"{relative_path} (error calculating hash)")
                    elif hash1 != hash2:
                        # Hashes differ, but sizes/mtimes were close. Still different.
                        if source_item.mtime_ns > target_item.mtime_ns:
                            # Store path, source size, and target size for source newer files
                            comparison_results_dict[REPORT_DIFFERENT_CONTENT_SOURCE_NEWER].append((relative_path, source_item.size, target_item.size))
                        else:
                            # Store path, source size, and target size for target newer files
                            comparison_results_dict[REPORT_DIFFERENT_CONTENT_TARGET_NEWER].append((relative_path, source_item.size, target_item.size))
                    else:
                        # Hashes identical, mtime within tolerance, size identical. Truly identical.
                        # Store path and size for identical files
                        comparison_results_dict[REPORT_IDENTICAL].append((relative_path, source_item.size))
                else:
                    # No hash check, mtime within tolerance, size identical. Consider identical.
                    # Store path and size for identical files
                    comparison_results_dict[REPORT_IDENTICAL].append((relative_path, source_item.size))
            else:
                # mtime outside tolerance. Different content (even if sizes match).
                if source_item.mtime_ns > target_item.mtime_ns:
                    # Store path, source size, and target size for source newer files
                    comparison_results_dict[REPORT_DIFFERENT_CONTENT_SOURCE_NEWER].append((relative_path, source_item.size, target_item.size))
                else:
                    # Store path, source size, and target size for target newer files
                    comparison_results_dict[REPORT_DIFFERENT_CONTENT_TARGET_NEWER].append((relative_path, source_item.size, target_item.size))
        
        except OSError as e:
            comparison_results_dict[REPORT_COMPARE_ERROR].append(f"{relative_path} (file access error during comparison: {e})")
        except Exception as e:
            comparison_results_dict[REPORT_COMPARE_ERROR].append(f"{relative_path} (unexpected comparison error: {e})")
    print("Finished comparing items")
    return comparison_results_dict


# --- Argument Parsing Function ---
def getArguments():
    """
    Sets up and parses command-line arguments for the folder comparison tool.

    Returns:
        argparse.Namespace: An object containing the parsed arguments.
    """
    WRAP_WIDTH = 78 

    main_description_raw = "Compares folders based on existence, modification dates, size, and optionally SHA256/MD5 hash, generating a detailed report."
    main_description_wrapped = textwrap.fill(main_description_raw, width=WRAP_WIDTH)

    comparison_logic_raw = """
File Comparison Logic:
1. Initial Size Comparison:
   - If file sizes differ, files are immediately classified as "DIFFERENT_CONTENT".
     They are then differentiated by "SOURCE is newer" or "TARGET is newer" based on their modification time (mtime).
2. Modification Time (mtime) Comparison (if sizes are identical):
   - If abs(source_mtime - target_mtime) <= --time-tolerance (mtime within tolerance):
     - If --hash-check is NOT specified: Files are classified as "IDENTICAL".
     - If --hash-check IS specified: A hash check is performed.
       - If hashes are identical: Files are classified as "IDENTICAL".
       - If hashes are different: Files are classified as "DIFFERENT_CONTENT" (and differentiated by mtime).
   - If abs(source_mtime - target_mtime) > --time-tolerance (mtime OUTSIDE tolerance):
     - Files are classified as "DIFFERENT_CONTENT" (and differentiated by mtime).
     - A hash check is NOT performed, as the mtime difference is sufficient to mark them as different.
"""
    
    wrapped_comparison_logic_lines = []
    for line in comparison_logic_raw.splitlines():
        if not line.strip():
            wrapped_comparison_logic_lines.append("")
            continue
        
        leading_spaces = len(line) - len(line.lstrip())
        indent = " " * leading_spaces
        content = line.lstrip()

        wrapped_content = textwrap.fill(content, 
                                        width=WRAP_WIDTH - leading_spaces, 
                                        initial_indent=indent, 
                                        subsequent_indent=indent)
        wrapped_comparison_logic_lines.append(wrapped_content)
    
    full_description_with_logic = main_description_wrapped + "\n" + "\n".join(wrapped_comparison_logic_lines)

    # Custom usage string with '--' and specific formatting
    custom_usage_string_formatted = (
        'usage: %(prog)s [-h] [--ignore-case]\n'
        '                                  [--exclude [EXCLUDE [EXCLUDE ...]]]\n'
        '                                  [--exclude-file EXCLUDE_FILE]\n'
        '                                  [--time-tolerance TIME_TOLERANCE]\n'
        '                                  [--hash-check [{md5,sha256}]]\n'
        '                                  [--debug-exclude]\n'
        '                                  [--debug-exclude-filter-patterns [DEBUG_EXCLUDE_FILTER_PATTERNS [DEBUG_EXCLUDE_FILTER_PATTERNS ...]]]\n'
        '                                  -- source_folder target_folder'
    )

    parser = argparse.ArgumentParser(
        usage=custom_usage_string_formatted, 
        description=full_description_with_logic,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=None
    )

    parser.add_argument("source_folder", help="The path to the source folder.")
    parser.add_argument("target_folder", help="The path to the target folder.")
    parser.add_argument("--ignore-case", action="store_true", help="Perform case-insensitive comparison of file paths.")
    parser.add_argument("--exclude", nargs='*', default=[],
                        help="One or more shell-style patterns (e.g., '*.tmp' 'project/temp*' 'cache/') to exclude files or folders. "
                             "Directory patterns should end with a slash.")
    parser.add_argument("--exclude-file", help="Path to a file containing shell-style patterns to exclude (one pattern per line, # for comments).")
    parser.add_argument("--time-tolerance", type=float, default=1.0,
                        help="Maximum time difference in seconds (e.g., 0.001 for 1ms) "
                             "for two file modification timestamps to be considered IDENTICAL, along with identical size. "
                             "Default is 1.0. This option is used as a primary filter before hash check. "
                             "If files have identical size but their timestamps are outside this tolerance, "
                             "they are considered DIFFERENT, even if --hash-check is enabled. "
                             "Note: Sometimes, when manipulating files, the modification timestamp may be "
                             "rounded to the nearest second. Using --time-tolerance 1.0 (the default) is "
                             "recommended to treat such files as identical if their size and (optionally) hash also match.")
    parser.add_argument("--hash-check", choices=['md5', 'sha256'], nargs='?', const='md5',
                        help="If enabled, perform a content hash comparison for files "
                             "that have identical sizes and timestamps within time-tolerance to confirm identity "
                             "more rigorously. Specify 'md5' or 'sha256' as the algorithm. "
                             "Defaults to MD5 if no algorithm is specified. "
                             "The hash check is performed ONLY if sizes are identical AND "
                             "timestamps are within the specified time-tolerance.")
    parser.add_argument("--debug-exclude", action="store_true", help="Enable verbose debugging output for exclusion pattern matching.")
    parser.add_argument("--debug-exclude-filter-patterns", nargs='*', default=[],
                        help="When --debug-exclude is enabled, only print debug messages for paths containing one of these substring patterns (e.g., '.aienv*' '.texlive*').")

    return parser.parse_args()


# --- Formatin date Function ---
def get_formatted_dates():
    """
    Generates and returns formatted local and UTC date strings.

    Returns:
        tuple: A tuple containing (local_date_str, utc_date_str).
    """
    now_local = datetime.datetime.now()
    now_utc = datetime.datetime.utcnow()

    # Calculate UTC offset for local time
    utc_offset_seconds = time.altzone if time.daylight else time.timezone
    utc_offset_hours = -utc_offset_seconds / 3600.0

    if utc_offset_hours == int(utc_offset_hours):
        local_offset_str = f"UTC{'+' if utc_offset_hours >= 0 else ''}{int(utc_offset_hours)}"
    else:
        sign = '+' if utc_offset_hours >= 0 else ''
        hours = int(abs(utc_offset_hours))
        minutes = int((abs(utc_offset_hours) - hours) * 60)
        local_offset_str = f"UTC{sign}{hours:02d}:{minutes:02d}"

    local_date_str = now_local.strftime(f"%a %b %d %H:%M:%S {local_offset_str} %Y")
    utc_date_str = now_utc.strftime("%a %b %d %H:%M:%S UTC %Y")

    return local_date_str, utc_date_str

def format_size_human_readable(size_in_bytes):
    """
    Converts a size in bytes to a human-readable format (B, KB, MB, GB, TB).
    Returns "None bytes" if size_bytes is None.

    Exemples d'utilisation:
    print(format_size_human_readable(0))                   # 0    Bytes
    print(format_size_human_readable(100))                 # 100  Bytes
    print(format_size_human_readable(1023))                # 1023 Bytes
    print(format_size_human_readable(1024))                # 1.0  KB
    print(format_size_human_readable(1500))                # 1.46 KB
    print(format_size_human_readable(1024 * 1024))         # 1.0  MB
    print(format_size_human_readable(5 * (1024**3)))       # 5.0  GB
    print(format_size_human_readable(2.5 * (1024**4)))     # 2.5  TB
    print(format_size_human_readable(1234567890))          # 1.15 GB
    print(format_size_human_readable(9876543210987654321)) # 8.59 EB (Exabytes)
    """
    if size_in_bytes is None:
        return "None bytes"

    if size_in_bytes == 0:
        return "0 Bytes"

    if size_in_bytes < 0:
        PM=-1.
        size_in_bytes = size_in_bytes * PM
    else:
        PM=1.

    # List of units : Bytes, Kilobytes, Megabytes, Gigabytes, Terabytes, Petabytes, etc.
    units = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']

    # Calculates the index of the appropriate unit
    # Ex: for 1024 Bytes, log base 1024 of 1024 is 1, so KB (index 1)
    # For 1023 Bytes, log base 1024 of 1023 is 0.99..., floor gives 0, so Bytes (index 0)
    i = int(math.floor(math.log(size_in_bytes, 1024)))

    # Ensure that the index does not exceed the number of units available
    if i >= len(units):
        i = len(units) - 1 # Use the largest unit available

    # Calculates the value in the chosen unit
    power = 1024 ** i
    formatted_value = PM*round(size_in_bytes / power, 2) # Rounded to 2 decimal places
    size_in_bytes = size_in_bytes * PM

    return f"{formatted_value} {units[i]}"

def _print_category_details(
    category_key: str,
    items: list,
    source_items_scanned: dict,
    target_items_scanned: dict,
    source_folder_cleaned: str,
    target_folder_cleaned: str,
    hash_check: str,
    category_number: int
):
    """
    Helper function to print details and totals for each comparison category.
    This consolidates the logic previously duplicated across print_report's elifs.
    """
    current_dirs = 0
    current_files = 0
    # Initialize counters for totals that are not directly 'current_dirs' or 'current_files'
    # as we will re-calculate them based on the unified loop
    total_items_in_category = 0
    total_dirs_in_category = 0
    total_files_in_category = 0
    current_size = 0 # Accumulates total_size for the current category
    # Specific totals for categories 6 and 7 for net change calculation
    temp_target_older_size_cat6 = 0 # Total of target_size for REPORT_DIFFERENT_CONTENT_SOURCE_NEWER
    temp_source_older_size_cat7 = 0 # Total of source_size for REPORT_DIFFERENT_CONTENT_TARGET_NEWER

    # --- Step 1: Calculate totals by iterating through items ---
    # This loop calculates all necessary sums/counts BEFORE printing anything

    # Initialize separate totals for REPORT_EXCLUDED
    src_excl_total_items = 0
    src_excl_total_dirs = 0
    src_excl_total_files = 0
    src_excl_total_size_bytes = 0

    tgt_excl_total_items = 0
    tgt_excl_total_dirs = 0
    tgt_excl_total_files = 0
    tgt_excl_total_size_bytes = 0

    for item_tuple in items:
        total_items_in_category += 1
        item_path = None
        item_size = None
        item_is_dir = False

        if category_key == REPORT_ONLY_IN_SOURCE:
            item_path, item_size = item_tuple
            original_item = source_items_scanned.get(item_path)
            if original_item:
                item_is_dir = original_item.is_dir
            elif item_path.endswith(os.sep): # Fallback if not found in scanned_items (e.g., root folder itself)
                item_is_dir = True
            # For items that are not in scanned_items (e.g. root dir itself), we can't reliably get type/size without re-statting

        elif category_key == REPORT_ONLY_IN_TARGET:
            item_path, item_size = item_tuple
            original_item = target_items_scanned.get(item_path)
            if original_item:
                item_is_dir = original_item.is_dir
            elif item_path.endswith(os.sep):
                item_is_dir = True

        elif category_key == REPORT_IDENTICAL:
            item_path, item_size = item_tuple
            item_is_dir = (item_size is None) # Convention: size=None for directories

        elif category_key == REPORT_DIFFERENT_CONTENT_SOURCE_NEWER:
            item_path, source_size, target_size = item_tuple
            item_size = source_size # We sum source_size for this category
            item_is_dir = (item_size is None) # Convention: size=None for directories
            if target_size is not None:
                temp_target_older_size_cat6 += target_size

        elif category_key == REPORT_DIFFERENT_CONTENT_TARGET_NEWER:
            item_path, source_size, target_size = item_tuple
            item_size = target_size # We sum target_size for this category
            item_is_dir = (item_size is None) # Convention: size=None for directories
            if source_size is not None:
                temp_source_older_size_cat7 += source_size

        elif category_key == REPORT_EXCLUDED:
            # item_tuple is (relative_path, matched_pattern, current_scan_folder_basename, is_source_scan_flag, is_dir, size)
            item_path, _, _, is_source_item, item_is_dir, item_size = item_tuple

            # Accumulate for individual source/target excluded totals
            if is_source_item:
                src_excl_total_items += 1
                if item_is_dir:
                    src_excl_total_dirs += 1
                else:
                    src_excl_total_files += 1
                    if item_size is not None:
                        src_excl_total_size_bytes += item_size
            else:
                tgt_excl_total_items += 1
                if item_is_dir:
                    tgt_excl_total_dirs += 1
                else:
                    tgt_excl_total_files += 1
                    if item_size is not None:
                        tgt_excl_total_size_bytes += item_size

        elif category_key == REPORT_DIFFERENT_TYPE:
            item_path, type_desc = item_tuple
            # Infer is_dir from type_desc or path suffix for totals
            item_is_dir = "Directory" in type_desc or item_path.endswith(os.sep)
            item_size = None # No meaningful size for type differences

        elif category_key in [REPORT_BROKEN_SYMLINK_SOURCE, REPORT_BROKEN_SYMLINK_TARGET]:
            item_path = item_tuple # Item is just the path string
            # Determine the full path of the symbolic link for os.lstat
            full_symlink_path = os.path.join(source_folder_cleaned if category_key == REPORT_BROKEN_SYMLINK_SOURCE else target_folder_cleaned, item_path)
            try:
                # Use os.lstat to get information about the symbolic link file
                item_size = os.lstat(full_symlink_path).st_size
            except OSError:
                # If os.lstat fails (e.g., link disappeared between scan and print), 0 is considered for the total
                item_size = 0
            item_is_dir = False # A symbolic link is always considered a file, not a directory
            
        elif category_key == REPORT_COMPARE_ERROR:
            item_path = item_tuple[0] if isinstance(item_tuple, tuple) else item_tuple
            item_is_dir = item_path.endswith(os.sep) if isinstance(item_path, str) else False
            item_size = None # No size for errors

        # Accumulate overall totals for the category
        if item_is_dir:
            total_dirs_in_category += 1
        else:
            total_files_in_category += 1
            if item_size is not None:
                current_size += item_size # This accumulates total_size_bytes

    # --- Step 2: Print totals for the current category (after calculation, before listing items) ---
    if category_key == REPORT_EXCLUDED:
        # Print grand total for all excluded items
        print(f"    Total: {total_items_in_category} items, size {format_size_human_readable(current_size)} ({total_dirs_in_category} directories, {total_files_in_category} files)")

        # Print source_dir excluded total
        if src_excl_total_items > 0:
            print(f"    source_dir total: {src_excl_total_items} items, size {format_size_human_readable(src_excl_total_size_bytes)} ({src_excl_total_dirs} directories, {src_excl_total_files} files)")
        else:
            print(f"    source_dir total: {src_excl_total_items} items")

        # Print target_dir excluded total
        if tgt_excl_total_items > 0:
            print(f"    target_dir total: {tgt_excl_total_items} items, size {format_size_human_readable(tgt_excl_total_size_bytes)} ({tgt_excl_total_dirs} directories, {tgt_excl_total_files} files)")
        else:
            print(f"    target_dir total: {tgt_excl_total_items} items")

    elif category_key in [REPORT_DIFFERENT_CONTENT_SOURCE_NEWER, REPORT_DIFFERENT_CONTENT_TARGET_NEWER]:
        # These categories always refer to files only (directories handled by mtime comparison for identity)
        print(f"    Total: {total_files_in_category} files, size {format_size_human_readable(current_size)}")
        if category_key == REPORT_DIFFERENT_CONTENT_SOURCE_NEWER and total_files_in_category > 0:
            net_change = format_size_human_readable(current_size - temp_target_older_size_cat6)
            print(f"    Net change in target_dir size if old files were replaced by\n    new files from source_dir: {net_change}")
        elif category_key == REPORT_DIFFERENT_CONTENT_TARGET_NEWER and total_files_in_category > 0:
            net_change = format_size_human_readable(current_size - temp_source_older_size_cat7)
            print(f"    Net change in source_dir size if old files were replaced by\n    new files from target_dir: {net_change}")
    else: # All other categories (1, 2, 3, 4, 5, 9, 10)
        if total_items_in_category > 0:
            # Only print size/counts if applicable (i.e., if there are files or dirs or size > 0)
            if total_files_in_category > 0 or total_dirs_in_category > 0 or current_size > 0:
                print(f"    Total: {total_items_in_category} items, size {format_size_human_readable(current_size)} ({total_dirs_in_category} directories, {total_files_in_category} files)")
            else: # If no size/dirs/files (e.g. only broken symlinks or errors without size info)
                 print(f"    Total: {total_items_in_category} items")
        else:
            print(f"    Total: {total_items_in_category} items")

    # --- Step 3: Print individual items (after totals) ---
    if items:
        for item_tuple in sorted(items, key=lambda x: x[0] if isinstance(x, tuple) else x):
            if category_key == REPORT_ONLY_IN_SOURCE:
                item_path, item_size = item_tuple
                print(f"      {item_path} (source size: {format_size_human_readable(item_size)})")
            elif category_key == REPORT_ONLY_IN_TARGET:
                item_path, item_size = item_tuple
                print(f"      {item_path} (target size: {format_size_human_readable(item_size)})")
            elif category_key == REPORT_IDENTICAL:
                item_path, item_size = item_tuple
                print(f"      {item_path} (size: {format_size_human_readable(item_size)})")
            elif category_key == REPORT_DIFFERENT_CONTENT_SOURCE_NEWER:
                item_path, source_size, target_size = item_tuple
                print(f"      {item_path} (source size: {format_size_human_readable(source_size)}, target size: {format_size_human_readable(target_size)})")
            elif category_key == REPORT_DIFFERENT_CONTENT_TARGET_NEWER:
                item_path, source_size, target_size = item_tuple
                print(f"      {item_path} (source size: {format_size_human_readable(source_size)}, target size: {format_size_human_readable(target_size)})")
            elif category_key == REPORT_EXCLUDED:
                item_path, matched_pattern, _, is_source_scan_flag, _, item_size = item_tuple
                if is_source_scan_flag:
                    print(f"      {item_path} (source size: {format_size_human_readable(item_size)}, matched by '{matched_pattern}')")
                else:
                    print(f"      {item_path} (target size: {format_size_human_readable(item_size)}, matched by '{matched_pattern}')")
            elif category_key == REPORT_DIFFERENT_TYPE:
                item_path, type_desc = item_tuple
                print(f"      {item_path} ({type_desc})")
            elif category_key in [REPORT_BROKEN_SYMLINK_SOURCE, REPORT_BROKEN_SYMLINK_TARGET]:
                # item_tuple is just the path string here
                item_path = item_tuple
                full_symlink_path = os.path.join(source_folder_cleaned if category_key == REPORT_BROKEN_SYMLINK_SOURCE else target_folder_cleaned, item_path)
                individual_item_size = None
                try:
                    individual_item_size = os.lstat(full_symlink_path).st_size
                except OSError:
                    individual_item_size = None # If lstat fails again, display "None bytes"
                print(f"      {item_path} (size: {format_size_human_readable(individual_item_size)})")
            elif category_key == REPORT_COMPARE_ERROR: # Indent this block correctly
                if isinstance(item_tuple, tuple): # For (path, message) format
                    print(f"      {item_tuple[0]} ({item_tuple[1]})")
                else:
                    print(f"      {item_tuple}") # For simple string messages
    print() # Add blank line between categories

def print_report(
    comparison_results_dict,
    args,
    source_folder_cleaned,
    target_folder_cleaned,
    source_items_scanned,
    target_items_scanned,
    elapsed_time_cpu,
    local_date_str,
    SCRIPT_VERSION,
    SCRIPT_DATE,
    all_exclude_patterns,
    num_patterns_from_exclude_file,
    REPORT_BROKEN_SYMLINK_SOURCE,
    REPORT_BROKEN_SYMLINK_TARGET,
    REPORT_ONLY_IN_SOURCE,
    REPORT_ONLY_IN_TARGET,
    REPORT_IDENTICAL,
    REPORT_DIFFERENT_CONTENT_SOURCE_NEWER,
    REPORT_DIFFERENT_CONTENT_TARGET_NEWER,
    REPORT_EXCLUDED,
    REPORT_DIFFERENT_TYPE,
    REPORT_COMPARE_ERROR
):
    """
    Prints a detailed comparison report based on the provided results.
    """

    max_label_len = len("Exclusion patterns loaded from file")

    print("\n" + "="*80)
    print("--------------------------- Folder Comparison Report ---------------------------")
    print("="*80)

    print(f"\n{'Date':<{max_label_len}}: {local_date_str}")
    print(f"{'folder_comparator.py':<{max_label_len}}: version {SCRIPT_VERSION} ({SCRIPT_DATE})")
    print(f"{'source_dir':<{max_label_len}}: {source_folder_cleaned}")
    print(f"{'target_dir':<{max_label_len}}: {target_folder_cleaned}")
    print(f"{'Time Tolerance for IDENTICAL Files':<{max_label_len}}: {args.time_tolerance} seconds")
    if args.hash_check:
        hash_status_or_type = str(args.hash_check)
    else:
        hash_status_or_type = 'Disabled'
    if args.hash_check:
        description_in_parentheses = "(Files considered IDENTICAL based"+f"\n{'':{max_label_len}}  on identical size and timestamp within"+f"\n{'':{max_label_len}}  tolerance, AND identical hash)"
    else:
        description_in_parentheses = "(Files considered IDENTICAL based"+f"\n{'':{max_label_len}}  on identical size and timestamp within"+f"\n{'':{max_label_len}}  tolerance)"
    print(f"{'Hash Check':<{max_label_len}}: {hash_status_or_type} {description_in_parentheses}")

    # Exclusion patterns summary
    if all_exclude_patterns:
        # Check if patterns were loaded from a file
        if args.exclude_file:
            # Print the file name and the number of patterns read from this file
            print(f"{{:<{max_label_len}}}: {{}} ({{}} patterns)".format(
                "Exclusion patterns loaded from file", args.exclude_file, num_patterns_from_exclude_file
            ))

        # Check if patterns were provided directly via --exclude argument
        # This assumes args.exclude is a list of strings if used, or None/empty if not.
        if args.exclude:
            print(f"{{:<{max_label_len}}}: {{}}".format(
                "Exclusion patterns from --exclude", ", ".join(args.exclude)
            ))

        # Print the total number of effective exclusion patterns
        print(f"{{:<{max_label_len}}}: {{}} patterns".format(
            "Total exclusion patterns in effect", len(all_exclude_patterns)
        ))

        # Print the complete list of all effective exclusion patterns
        print(f"{', '.join(all_exclude_patterns)}")
    else:
        print("No exclusion patterns in effect.")

    print("\nNote on Size Calculation Logic:")
    print("- Regular Files  :  Their actual byte size is used.")
    print("- Directories    :  Have no meaningful 'content size' in bytes.")
    print("                    Their size is recorded as 'None' during scanning and")
    print("                    displayed as 'None bytes' in the report.")
    print("                    They are not included in total size sums.")
    print("- Symbolic Links :  The size recorded is the actual size of the symlink")
    print("                    entry itself (i.e., the byte length of the target")
    print("                    path string it contains), not the size of its target.")
    print("                    This size is a numerical value, displayed as 'XX bytes',")
    print("                    and included in total size sums where applicable.")
    print("\n" + "-"*80)

    # Define the fixed order and print titles for the 10 comparison categories
    report_categories_fixed_order = [
        (REPORT_BROKEN_SYMLINK_SOURCE, "Broken Symlinks in source_dir"),
        (REPORT_BROKEN_SYMLINK_TARGET, "Broken Symlinks in target_dir"),
        (REPORT_ONLY_IN_SOURCE, "Items existing ONLY in source_dir"),
        (REPORT_ONLY_IN_TARGET, "Items existing ONLY in target_dir"),
        (REPORT_IDENTICAL, "Items existing in source_dir AND target_dir that are IDENTICAL"),
        (REPORT_DIFFERENT_CONTENT_SOURCE_NEWER, "Items existing in source_dir AND target_dir that are DIFFERENT and NEWER in source_dir"),
        (REPORT_DIFFERENT_CONTENT_TARGET_NEWER, "Items existing in source_dir AND target_dir that are DIFFERENT and NEWER in target_dir"),
        (REPORT_EXCLUDED, "Excluded Items"),
        (REPORT_DIFFERENT_TYPE, "Items existing in source_dir AND target_dir that have DIFFERENT Type (File vs. Folder)"),
        (REPORT_COMPARE_ERROR, "Comparison Errors")
    ]

    print ()
    for i, (category_key, category_title) in enumerate(report_categories_fixed_order):
        # Dynamically addapt category_title for REPORT_IDENTICAL based on hash_check
        display_category_title = category_title
        if category_key == REPORT_IDENTICAL:
            hash_part = ", AND identical hash." if args.hash_check else ", NO HASH-CHECK."
            display_category_title = (
                #f"Files in Source AND Target that are IDENTICAL\n"
                f"{category_title}\n"
                f"{' ':4}(same size AND timestamps within tolerance{hash_part})"
            )

        print(f"{i + 1:2}. {display_category_title}")

        items = comparison_results_dict.get(category_key, []) # Use .get to be safe

        _print_category_details(category_key, items, source_items_scanned, target_items_scanned,
                                source_folder_cleaned, target_folder_cleaned, args.hash_check,
                                i + 1) # Pass the actual category number (i + 1)



    print(f"\nTotal CPU elapsed wall clock time: {elapsed_time_cpu:.2f} seconds") #
    print("\n" + "="*80)
    print("-------------------------------- End of Report ---------------------------------") #
    print("="*80)

def main():
    print()

    # --- Python Version Check ---
    # Define the minimum required Python version (e.g., 3.8 for standard fnmatch.translate behavior)
    MIN_PYTHON_VERSION = (3, 8)
    if sys.version_info < MIN_PYTHON_VERSION:
        print(f"Error: This script requires Python {MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]} or higher.", file=sys.stderr)
        print(f"You are currently using Python {sys.version_info.major}.{sys.version_info.minor}.", file=sys.stderr)
        print("Please use `python3.11` if available, or upgrade your Python version.", file=sys.stderr)
        sys.exit(1)

    start_time_cpu = time.perf_counter() # Use perf_counter for CPU time
    local_date_str, utc_date_str = get_formatted_dates()

    # Initialize the dictionary to store comparison results
    comparison_results_dict = {
        REPORT_BROKEN_SYMLINK_SOURCE: [],
        REPORT_BROKEN_SYMLINK_TARGET: [],
        REPORT_ONLY_IN_SOURCE: [],
        REPORT_ONLY_IN_TARGET: [],
        REPORT_IDENTICAL: [],
        REPORT_DIFFERENT_CONTENT_SOURCE_NEWER: [],
        REPORT_DIFFERENT_CONTENT_TARGET_NEWER: [],
        REPORT_EXCLUDED: [],
        REPORT_DIFFERENT_TYPE: [],
        REPORT_COMPARE_ERROR: []
    }

    args = getArguments()

    # Set global debug flags based on arguments
    DEBUG_EXCLUDE_ENABLED = args.debug_exclude
    DEBUG_TARGET_PATTERNS = args.debug_exclude_filter_patterns

    global all_exclude_patterns
    global num_patterns_from_exclude_file

    # Add patterns from command line
    if args.exclude:
        all_exclude_patterns.extend(args.exclude)

    # Add patterns from exclude file
    if args.exclude_file:
        try:
            if os.path.exists(args.exclude_file):
                patterns_read_from_file_temp = [] # Use a temporary list to count patterns in the file
                with open(args.exclude_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        stripped_line = line.strip()
                        if stripped_line and not stripped_line.startswith('#'):
                            patterns_read_from_file_temp.append(stripped_line)

                num_patterns_from_exclude_file = len(patterns_read_from_file_temp) # Store the number of patterns in the file
                all_exclude_patterns.extend(patterns_read_from_file_temp) # Add these patterns to the global list
            else:
                print(f"Error: Exclusion file '{args.exclude_file}' not found.", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"Error reading exclusion file '{args.exclude_file}': {e}", file=sys.stderr)
            sys.exit(1)

    # Clean and validate folder paths
    source_folder_cleaned = os.path.abspath(args.source_folder)
    target_folder_cleaned = os.path.abspath(args.target_folder)

    if not os.path.isdir(source_folder_cleaned):
        print(f"Error: Source folder '{source_folder_cleaned}' not found or is not a directory.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(target_folder_cleaned):
        print(f"Error: Target folder '{target_folder_cleaned}' not found or is not a directory.", file=sys.stderr)
        sys.exit(1)
    
    # Compile patterns once before comparison starts
    # This call sets patterns_compiled_flag = True and populates global lists
    compiled_file_patterns_global, compiled_dir_patterns_global = compile_exclusion_patterns(all_exclude_patterns)
    patterns_compiled_flag = True # Set flag after compilation

    # Perform initial scans to populate broken symlinks and excluded items
    # and get lists of non-excluded items for comparison
    source_items_scanned = _scan_folder(source_folder_cleaned, comparison_results_dict, True, args.ignore_case)
    target_items_scanned = _scan_folder(target_folder_cleaned, comparison_results_dict, False, args.ignore_case)

    # Perform comparison of non-excluded items
    comparison_results_dict = compare_scanned_items(source_items_scanned, target_items_scanned, comparison_results_dict, args.time_tolerance, args.hash_check)

    end_time_cpu = time.perf_counter() #
    elapsed_time_cpu = end_time_cpu - start_time_cpu #

    # --- Print Comparison Report ---
    print_report(
        comparison_results_dict,
        args,
        source_folder_cleaned,
        target_folder_cleaned,
        source_items_scanned,
        target_items_scanned,
        elapsed_time_cpu,
        local_date_str,
        SCRIPT_VERSION,
        SCRIPT_DATE,
        all_exclude_patterns,
        num_patterns_from_exclude_file,
        REPORT_BROKEN_SYMLINK_SOURCE,
        REPORT_BROKEN_SYMLINK_TARGET,
        REPORT_ONLY_IN_SOURCE,
        REPORT_ONLY_IN_TARGET,
        REPORT_IDENTICAL,
        REPORT_DIFFERENT_CONTENT_SOURCE_NEWER,
        REPORT_DIFFERENT_CONTENT_TARGET_NEWER,
        REPORT_EXCLUDED,
        REPORT_DIFFERENT_TYPE,
        REPORT_COMPARE_ERROR
    )

if __name__ == "__main__":
    main()
