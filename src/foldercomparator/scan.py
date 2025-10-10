import os

from src.foldercomparator.utils import calculate_hash
from src.foldercomparator.excluded import is_excluded

from src.foldercomparator import (
    REPORT_IDENTICAL,
    REPORT_EXCLUDED,
    REPORT_COMPARE_ERROR,
    REPORT_DIFFERENT_TYPE,
    REPORT_ONLY_IN_SOURCE,
    REPORT_ONLY_IN_TARGET,
    DEBUG_EXCLUDE_ENABLED,
    REPORT_BROKEN_SYMLINK_SOURCE,
    REPORT_BROKEN_SYMLINK_TARGET,
    REPORT_DIFFERENT_CONTENT_TARGET_NEWER,
    REPORT_DIFFERENT_CONTENT_SOURCE_NEWER,
)

class ScannedItem:
    def __init__(self, full_path, is_dir, size, mtime_ns, is_symlink, symlink_target=None):
        self.full_path = full_path
        self.is_dir = is_dir
        self.size = size
        self.mtime_ns = mtime_ns # Use nanoseconds for precision, convert to seconds when needed
        self.is_symlink = is_symlink
        self.symlink_target = symlink_target # Stores the target path if it's a symlink


def scan_folder(
                    compiled_file_patterns_global,
                compiled_dir_patterns_global,
                compiled_root_specific_file_patterns_global,
                compiled_root_specific_dir_patterns_global,
                debug_exclude,
                debug_target,
    root_path, comparison_results_dict, is_source_scan_flag, ignore_case):
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
            is_excluded_flag, matched_pattern = is_excluded(
                compiled_file_patterns_global,
                compiled_dir_patterns_global,
                compiled_root_specific_file_patterns_global,
                compiled_root_specific_dir_patterns_global,
                debug_exclude,
                debug_target,
                relative_path_with_sep, True, current_scan_folder_basename)
            if is_excluded_flag:
                if DEBUG_EXCLUDE_ENABLED:
                    print(f"DEBUG EXCLUDE (DIR): {current_scan_folder_basename} - '{relative_path_with_sep}' matched by '{matched_pattern}'")
                comparison_results_dict[REPORT_EXCLUDED].append((relative_path_with_sep, matched_pattern, current_scan_folder_basename, is_source_scan_flag))
                dirnames.remove(dirname) # Prune this directory from further walk
                continue # Skip further processing for this excluded directory

            # If not excluded and not a broken symlink, add to scanned items for later comparison
            # Directories don't have size or mtime for comparison purposes
            # Store lowercased key if ignore_case is true for consistent dictionary lookup
            key_path = relative_path.lower() if ignore_case else relative_path
            scanned_non_excluded_items[key_path] = ScannedItem(
                full_path=full_path,
                is_dir=True,
                size=None,
                mtime_ns=None,
                is_symlink=is_current_symlink,
                symlink_target=os.path.realpath(full_path) if is_current_symlink else None
            )

        # Process files
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            relative_path = os.path.join(current_relative_dir, filename)

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
            is_excluded_flag, matched_pattern = is_excluded(
                compiled_file_patterns_global,
                compiled_dir_patterns_global,
                compiled_root_specific_file_patterns_global,
                compiled_root_specific_dir_patterns_global,
                debug_exclude,
                debug_target,
                relative_path, False, current_scan_folder_basename)
            if is_excluded_flag:
                if DEBUG_EXCLUDE_ENABLED:
                    print(f"DEBUG EXCLUDE (FILE): {current_scan_folder_basename} - '{relative_path}' matched by '{matched_pattern}'")
                comparison_results_dict[REPORT_EXCLUDED].append((relative_path, matched_pattern, current_scan_folder_basename, is_source_scan_flag))
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

    total_size_target_older_cat6 = 0
    total_size_source_older_cat7 = 0

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
            comparison_results_dict[REPORT_DIFFERENT_TYPE].append(f"{relative_path} ({'Directory' if source_item.is_dir else 'File'} vs {'Directory' if target_item.is_dir else 'File'})")
            continue
        
        # At this point, both are either files or both are directories.

        # 3. If both are directories, they are identical (content is recursive, not simple size/mtime)
        if source_item.is_dir and target_item.is_dir:
            # Directories should have size None in the report.
            comparison_results_dict[REPORT_IDENTICAL].append((relative_path + os.sep, None))
            continue
        
        # At this point, both are files. Perform file content comparison.

        try:
            # 4. Compare Files - Size
            if source_item.size is None or target_item.size is None:
                # This case should ideally not happen if scan_folder populated size correctly for files.
                # It might happen if os.stat failed, which would be logged as a scanning error.
                # However, for robustness, if it does, log a comparison error.
                comparison_results_dict[REPORT_COMPARE_ERROR].append(f"{relative_path} (file size information missing during comparison)")
                continue
            
            if source_item.size != target_item.size:
                # Sizes differ, it's a different file. Determine newer based on mtime.
                if source_item.mtime_ns > target_item.mtime_ns:
                    # Store path, source size, and target size for source newer files
                    comparison_results_dict[REPORT_DIFFERENT_CONTENT_SOURCE_NEWER].append((relative_path, source_item.size, target_item.size))
                    total_size_target_older_cat6 += target_item.size
                else:
                    # Store path, source size, and target size for target newer files
                    comparison_results_dict[REPORT_DIFFERENT_CONTENT_TARGET_NEWER].append((relative_path, source_item.size, target_item.size))
                    total_size_source_older_cat7 += source_item.size
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
                            total_size_target_older_cat6 += target_item.size
                        else:
                            # Store path, source size, and target size for target newer files
                            comparison_results_dict[REPORT_DIFFERENT_CONTENT_TARGET_NEWER].append((relative_path, source_item.size, target_item.size))
                            total_size_source_older_cat7 += source_item.size
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
                    total_size_target_older_cat6 += target_item.size
                else:
                    # Store path, source size, and target size for target newer files
                    comparison_results_dict[REPORT_DIFFERENT_CONTENT_TARGET_NEWER].append((relative_path, source_item.size, target_item.size))
                    total_size_source_older_cat7 += source_item.size
        
        except OSError as e:
            comparison_results_dict[REPORT_COMPARE_ERROR].append(f"{relative_path} (file access error during comparison: {e})")
        except Exception as e:
            comparison_results_dict[REPORT_COMPARE_ERROR].append(f"{relative_path} (unexpected comparison error: {e})")
    print("Finished comparing items")

    return total_size_target_older_cat6, total_size_source_older_cat7