# --- Constants for Comparison Outcomes and Report Categories ---
# These are the 10 definitive report categories
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

patterns_compiled_flag = False
DEBUG_EXCLUDE_ENABLED = False

# --- Gloabl variables related to the exclusions patterns
num_patterns_from_exclude_file = 0

# --- Global variables for cleaned paths (set in main)
source_folder_cleaned = ""
target_folder_cleaned = ""

# --- Global variables for total size of the older source/target files
total_size_target_older_cat6 = 0 # Sum of sizes of TARGET files (older) for Category 6
total_size_source_older_cat7 = 0 # Sum of sizes of SOURCE files (older) for Category 7
