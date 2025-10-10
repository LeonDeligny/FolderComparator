import os
import sys
import time

from src.foldercomparator.arguments import get_arguments
from src.foldercomparator.utils import get_formatted_dates
from src.foldercomparator.printreport import print_report
from src.foldercomparator.scan import (
    scan_folder,
    compare_scanned_items,
)
from src.foldercomparator.excluded import (
    compile_exclusion_patterns,
)

from src.foldercomparator import (
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
    _, _ = compile_exclusion_patterns(
        debug_exclude=debug_exclude,
        debug_target=debug_target,
        patterns_list=all_exclude_patterns,
    )

    # Perform initial scans to populate broken symlinks and excluded items
    # and get lists of non-excluded items for comparison
    source_items_scanned = scan_folder(source_folder_cleaned, comparison_results_dict, True, args.ignore_case)
    target_items_scanned = scan_folder(target_folder_cleaned, comparison_results_dict, False, args.ignore_case)

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
        print(f"Error: This script requires Python {MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]} or higher.", file=sys.stderr)
        print(f"You are currently using Python {sys.version_info.major}.{sys.version_info.minor}.", file=sys.stderr)
        print("Please use `python3.11` if available, or upgrade your Python version.", file=sys.stderr)
        sys.exit(1)

    main()
