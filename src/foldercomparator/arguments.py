import textwrap
import argparse


def get_arguments():
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
