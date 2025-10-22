'''
# --- Script Description ---
#
SCRIPT_VERSION = "v25.06"
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

'''

import os
import sys
import time

from foldercomparator.arguments import get_arguments
from foldercomparator.utils import get_formatted_dates
from foldercomparator.printreport import print_report
from foldercomparator.scan import (
    scan_folder,
    compare_scanned_items,
)
from foldercomparator.excluded import (
    compile_exclusion_patterns,
)

from foldercomparator import (
    REPORT_BROKEN_SYMLINK_SOURCE,
    REPORT_BROKEN_SYMLINK_TARGET,
    REPORT_COMPARE_ERROR,
    REPORT_DIFFERENT_CONTENT_SOURCE_NEWER,
    REPORT_DIFFERENT_CONTENT_TARGET_NEWER,
    REPORT_DIFFERENT_TYPE,
    REPORT_EXCLUDED,
    REPORT_IDENTICAL,
    REPORT_ONLY_IN_SOURCE,
    REPORT_ONLY_IN_TARGET,
)

def main():
    start_time_cpu = time.perf_counter() # Use perf_counter for CPU time
    local_date_str, _ = get_formatted_dates()

    all_exclude_patterns = []
    
    # --- Global variables for optimization and debugging ---
    compiled_file_patterns_global = []
    compiled_dir_patterns_global = []
    compiled_root_specific_file_patterns_global = []
    compiled_root_specific_dir_patterns_global = []

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

    args = get_arguments()

    # Set global debug flags based on arguments
    debug_exclude = args.debug_exclude
    debug_target = args.debug_exclude_filter_patterns

    # Add patterns from command line
    if args.exclude:
        all_exclude_patterns.extend(args.exclude)
    else:
        print('No files to exclude.')

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
    else:
        num_patterns_from_exclude_file = 0

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
    compiled_file_patterns_global, compiled_dir_patterns_global = compile_exclusion_patterns(
        debug_exclude=debug_exclude,
        debug_target=debug_target,
        patterns_list=all_exclude_patterns,
    )

    # Perform initial scans to populate broken symlinks and excluded items
    # and get lists of non-excluded items for comparison
    source_items_scanned = scan_folder(
                        compiled_file_patterns_global,
                compiled_dir_patterns_global,
                compiled_root_specific_file_patterns_global,
                compiled_root_specific_dir_patterns_global,
                debug_exclude,
                debug_target,
source_folder_cleaned, comparison_results_dict, True, args.ignore_case)
    target_items_scanned = scan_folder(
                        compiled_file_patterns_global,
                compiled_dir_patterns_global,
                compiled_root_specific_file_patterns_global,
                compiled_root_specific_dir_patterns_global,
                debug_exclude,
                debug_target,
            target_folder_cleaned, comparison_results_dict, False, args.ignore_case)

    # Perform comparison of non-excluded items
    compare_scanned_items(source_items_scanned, target_items_scanned, comparison_results_dict, args.time_tolerance, args.hash_check)

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
    # --- Python Version Check ---
    # Define the minimum required Python version (e.g., 3.8 for standard fnmatch.translate behavior)
    MIN_PYTHON_VERSION = (3, 8)
    if sys.version_info < MIN_PYTHON_VERSION:
        print(
            "Error: This script requires Python",
            MIN_PYTHON_VERSION[0],
            ".",
            MIN_PYTHON_VERSION[1],
            " or higher.",
            file=sys.stderr,
        )
        print(
            "You are currently using Python ",
            sys.version_info.major,
            ".",
            sys.version_info.minor,
            file=sys.stderr,
        )
        print("Please use `python3.11` if available, or upgrade your Python version.", file=sys.stderr)
        sys.exit(1)

    main()
