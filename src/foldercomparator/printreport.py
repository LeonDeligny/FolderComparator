import os

from src.foldercomparator.utils import format_size_human_readable


def print_report(
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
):
    """
    Prints a detailed comparison report based on the provided results.
    """

    max_label_len = len("Exclusion patterns loaded from file")

    print("\n" + "="*80)
    print("--------------------------- Folder Comparison Report ---------------------------")
    print("="*80)

    print(f"\n{'Date':<{max_label_len}}: {local_date_str}")
    print(f"{'folder_comparator.py':<{max_label_len}}")
    print(f"{'Source':<{max_label_len}}: {source_folder_cleaned}")
    print(f"{'Target':<{max_label_len}}: {target_folder_cleaned}")
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
        if args.exclude_file:
            # Print the file name and the number of patterns read from this file
            print(f"{{:<{max_label_len}}}: {{}} ({{}} patterns)".format(
                "Exclusion patterns loaded from file", args.exclude_file, num_patterns_from_exclude_file
            ))
        else: # If no exclusion file was used
            # Print the patterns come from the command line
            print(f"{{:<{max_label_len}}}: From command line".format(
                "Exclusion patterns loaded from file"
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
    print("- Broken symlinks : There are reported separately and do not have a size")
    print("                    associated for comparison.")
    print("\n" + "-"*80)

    # Define the fixed order and titles for the 10 comparison categories, as per sortieAttendue.txt
    report_categories_fixed_order = [
        (REPORT_BROKEN_SYMLINK_SOURCE, REPORT_BROKEN_SYMLINK_SOURCE), #
        (REPORT_BROKEN_SYMLINK_TARGET, REPORT_BROKEN_SYMLINK_TARGET), #
        (REPORT_ONLY_IN_SOURCE, REPORT_ONLY_IN_SOURCE), #
        (REPORT_ONLY_IN_TARGET, REPORT_ONLY_IN_TARGET), #
        (REPORT_IDENTICAL, REPORT_IDENTICAL), #
        (REPORT_DIFFERENT_CONTENT_SOURCE_NEWER, REPORT_DIFFERENT_CONTENT_SOURCE_NEWER), #
        (REPORT_DIFFERENT_CONTENT_TARGET_NEWER, REPORT_DIFFERENT_CONTENT_TARGET_NEWER), #
        (REPORT_EXCLUDED, REPORT_EXCLUDED), #
        (REPORT_DIFFERENT_TYPE, REPORT_DIFFERENT_TYPE), #
        (REPORT_COMPARE_ERROR, REPORT_COMPARE_ERROR) #
    ]

    # Initialize counters for totals for summary
    total_source_only_dirs = 0
    total_source_only_files = 0
    total_source_only_size = 0
    total_target_only_dirs = 0
    total_target_only_files = 0
    total_target_only_size = 0
    total_identical_files = 0
    total_identical_size = 0
    total_diff_source_newer_files = 0
    total_diff_source_newer_size = 0
    total_diff_target_newer_files = 0
    total_diff_target_newer_size = 0
    total_size_target_older_cat6 = 0
    total_size_source_older_cat7 = 0

    for i, (category_key, category_title) in enumerate(report_categories_fixed_order):
        # Dynamically build the title for REPORT_IDENTICAL based on hash_check
        display_category_title = category_title
        if category_key == REPORT_IDENTICAL:
            hash_part = ", AND identical hash." if args.hash_check else ", NO HASH-CHECK."
            display_category_title = (
                f"Files in Source AND Target that are IDENTICAL\n"
                f"{' ':4}(same size AND timestamps within tolerance{hash_part})"
            )
        elif category_key == REPORT_EXCLUDED: # Preserve the special title for EXCLUDED if you have one
            display_category_title = "Excluded Files/Folders (based on --exclude patterns)."

        print(f"{i + 1:2}. {display_category_title}")

        items = comparison_results_dict.get(category_key, []) # Use .get to be safe

        # Custom total calculations and printing for specific categories as per sortieAttendue.txt
        if category_key == REPORT_ONLY_IN_SOURCE: #
            current_dirs = 0
            current_files = 0
            current_size = 0
            for item_tuple in items: # Iterate on item_tuple
                item_path, item_size = item_tuple # Add: Unpack the tuple
                # We can now directly use item_size from the tuple for total size calculation
                # original_item lookup is still useful to distinguish files/directories if needed
                original_item = source_items_scanned.get(item_path) # Removed .rstrip(os.sep) as item_path is now string
                if original_item: # If the item was found during the initial scan
                    if original_item.is_dir:
                        current_dirs += 1
                    else:
                        current_files += 1
                    if item_size is not None: # Use the size directly from the tuple
                        current_size += item_size
                else: # Fallback if item somehow not in scanned dict (e.g., if it was a broken symlink that also was only in source)
                    full_path_check = os.path.join(source_folder_cleaned, item_path) # Removed .rstrip(os.sep)
                    if os.path.isdir(full_path_check):
                        current_dirs += 1
                    elif os.path.isfile(full_path_check):
                        current_files += 1
                        try:
                            current_size += os.path.getsize(full_path_check) # Fallback to getsize for size
                        except OSError:
                            pass
            total_source_only_dirs = current_dirs
            total_source_only_files = current_files
            total_source_only_size = current_size
            print(f" "*4+f"Total: {total_source_only_dirs+total_source_only_files} items, size {format_size_human_readable(total_source_only_size)} ({total_source_only_dirs} directories, {total_source_only_files} files)") #
        elif category_key == REPORT_ONLY_IN_TARGET: #
            current_dirs = 0
            current_files = 0
            current_size = 0
            for item_tuple in items: # Iterate on item_tuple
                item_path, item_size = item_tuple # Add: Unpack the tuple
                original_item = target_items_scanned.get(item_path) # Removed .rstrip(os.sep)
                if original_item:
                    if original_item.is_dir:
                        current_dirs += 1
                    else:
                        current_files += 1
                    if item_size is not None: # Use the size directly from the tuple
                        current_size += item_size
                else:
                    full_path_check = os.path.join(target_folder_cleaned, item_path) # Removed .rstrip(os.sep)
                    if os.path.isdir(full_path_check):
                        current_dirs += 1
                    elif os.path.isfile(full_path_check):
                        current_files += 1
                        try:
                            current_size += os.path.getsize(full_path_check)
                        except OSError:
                            pass
            total_target_only_dirs = current_dirs
            total_target_only_files = current_files
            total_target_only_size = current_size
            print(f" "*4+f"Total: {total_target_only_dirs+total_target_only_files} items, size {format_size_human_readable(total_target_only_size)} ({total_target_only_dirs} directories, {total_target_only_files} files)") #
        elif category_key == REPORT_IDENTICAL:
            current_files = 0
            current_size = 0
            for item_tuple in items:
                item_path, item_size = item_tuple
                # Identify directory entries by their path ending with a separator AND a size of 0.
                # This distinguishes them from 0-byte files which do not end with a separator.
                is_directory_entry = item_path.endswith(os.sep) and item_size == 0

                if not is_directory_entry: # Only count as a file if it's not a directory entry
                    current_files += 1
                    # Add size only if it's not None (e.g., for valid files, including 0-byte files)
                    if item_size is not None:
                        current_size += item_size
            total_identical_files = current_files
            total_identical_size = current_size
            print(f" "*4+f"Total: {total_identical_files} files, size {format_size_human_readable(total_identical_size)}")
        elif category_key == REPORT_DIFFERENT_CONTENT_SOURCE_NEWER: #
            current_files = 0
            current_size = 0 # This will accumulate total_diff_source_newer_size (source_size)
            for item_tuple in items: # Iterate on item_tuple
                item_path, source_size, target_size = item_tuple # Add: Unpack the triple
                current_files += 1 # Always a file in this category

                if source_size is not None:
                    current_size += source_size # Accumulate source size for REPORT_DIFFERENT_CONTENT_SOURCE_NEWER total

                if target_size is not None:
                    total_size_target_older_cat6 += target_size # Accumulate target size for net change calculation
            total_diff_source_newer_files = current_files
            total_diff_source_newer_size = current_size # This now holds the sum of source_size for this category
            print(f" "*4+f"Total: {total_diff_source_newer_files} files, size {format_size_human_readable(total_diff_source_newer_size)}") #
            if total_diff_source_newer_files > 0:
                net_change = format_size_human_readable(total_diff_source_newer_size-total_size_target_older_cat6)
                print(f" "*4+f"Net change in target_dir size if old files were replaced by\n"+" "*4+f"new files from source_dir: {net_change}")
            #print(f"6. {net_change6.rjust(max_label_net_change)}"+" = Net change in size of target_dir if the old files\n"+" "*(max_label_net_change+6)+f"were replaced by the new ones from source_dir")
        elif category_key == REPORT_DIFFERENT_CONTENT_TARGET_NEWER: #
            current_files = 0
            current_size = 0 # This will accumulate total_diff_target_newer_size (target_size)
            for item_tuple in items: # Iterate on item_tuple
                item_path, source_size, target_size = item_tuple # Add: Unpack the triple
                current_files += 1 # Always a file in this category

                if target_size is not None:
                    current_size += target_size # Accumulate target size for REPORT_DIFFERENT_CONTENT_TARGET_NEWER total

                if source_size is not None:
                    total_size_source_older_cat7 += source_size # Accumulate source size for net change calculation
            total_diff_target_newer_files = current_files
            total_diff_target_newer_size = current_size # This now holds the sum of target_size for this category
            print(f" "*4+f"Total: {total_diff_target_newer_files} files, size {format_size_human_readable(total_diff_target_newer_size)}") #
            if total_diff_target_newer_files > 0:
                net_change = format_size_human_readable(total_diff_target_newer_size-total_size_source_older_cat7)
                print(f" "*4+f"Net change in source_dir size if old files were replaced by\n"+" "*4+f"new files from target_dir: {net_change}")
        elif category_key == REPORT_EXCLUDED:
            category_title = "Excluded Files/Folders (based on --exclude patterns)."
            source_excluded_items_list = []
            target_excluded_items_list = []
            # 'items' for REPORT_EXCLUDED now contains (item_path, matched_pattern, scan_folder_basename, is_source_item)
            for item_path, matched_pattern, scan_folder_basename, is_source_item in items:
                if is_source_item:
                    source_excluded_items_list.append((item_path, matched_pattern, scan_folder_basename))
                else:
                    target_excluded_items_list.append((item_path, matched_pattern, scan_folder_basename))

            # Sorting for consistent output
            source_excluded_items_list.sort(key=lambda x: x[0])
            target_excluded_items_list.sort(key=lambda x: x[0])

            print(f"    Total: Source {len(source_excluded_items_list)} items, Target {len(target_excluded_items_list)} items")
        elif category_key == REPORT_DIFFERENT_TYPE: #
            print(f" "*4+f"Total: {len(items)} items (files/directories)") #
        elif category_key == REPORT_BROKEN_SYMLINK_SOURCE:
            print(f" "*4+f"Total: {len(items)} items")
        elif category_key == REPORT_BROKEN_SYMLINK_TARGET:
            print(f" "*4+f"Total: {len(items)} items")
        else: # This 'else' now only handles REPORT_COMPARE_ERROR
            print(f" "*4+f"Total: {len(items)} items") #

        # Print items if present
        if items:
            # SPECIAL MANAGEMENT FOR EXCLUDED ITEMS
            if category_key == REPORT_EXCLUDED:
                if source_excluded_items_list:
                    print("    Source Excluded:")
                    for item_path, matched_pattern, _ in source_excluded_items_list:
                        print(f"      {item_path} (matched by '{matched_pattern}')")
                if target_excluded_items_list:
                    print("    Target Excluded:")
                    for item_path, matched_pattern, _ in target_excluded_items_list:
                        print(f"      {item_path} (matched by '{matched_pattern}')")
            elif category_key == REPORT_BROKEN_SYMLINK_SOURCE:
                if items: # Now 'items' is populated from comparison_results_dict
                    print("    Source Broken Symlinks:")
                    for item_path in sorted(items): # Iterate directly on 'items'
                        print(f"      {item_path}")
            elif category_key == REPORT_BROKEN_SYMLINK_TARGET:
                if items: # Now 'items' is populated from comparison_results_dict
                    print("    Target Broken Symlinks:")
                    for item_path in sorted(items): # Iterate directly on 'items'
                        print(f"      {item_path}")
            else: # This 'else' now handles all other categories except EXCLUDED and BROKEN_SYMLINKS
                for item_tuple in sorted(items): # Rename 'item' to 'item_tuple' for clarity
                    # Handle categories that now store (path, size) or (path, source_size, target_size)
                    if category_key == REPORT_ONLY_IN_SOURCE:
                        item_path, item_size = item_tuple
                        # Display 'None bytes' if item_size is None (for directories), otherwise display the actual size.
                        print(f"      {item_path} (source size: {'None bytes' if item_size is None else f'{item_size} bytes'})")
                    elif category_key == REPORT_ONLY_IN_TARGET:
                        item_path, item_size = item_tuple
                        # Display 'None bytes' if item_size is None (for directories), othe0rwise display the actual size.
                        print(f"      {item_path} (target size: {'None bytes' if item_size is None else f'{item_size} bytes'})")
                    elif category_key == REPORT_IDENTICAL:
                        item_path, item_size = item_tuple
                        # Display 'None bytes' if item_size is None (for directories), otherwise display the actual size.
                        print(f"      {item_path} (size: {'None bytes' if item_size is None else f'{item_size} bytes'})")
                    elif category_key == REPORT_DIFFERENT_CONTENT_SOURCE_NEWER:
                        item_path, source_size, target_size = item_tuple
                        # Display 'None bytes' if size is None, otherwise display the actual size for both source and target.
                        print(f"      {item_path} (source size: {'None bytes' if source_size is None else f'{source_size} bytes'}, target size: {'None bytes' if target_size is None else f'{target_size} bytes'})")
                    elif category_key == REPORT_DIFFERENT_CONTENT_TARGET_NEWER:
                        item_path, source_size, target_size = item_tuple
                        # Display 'None bytes' if size is None, otherwise display the actual size for both source and target.
                        print(f"      {item_path} (source size: {'None bytes' if source_size is None else f'{source_size} bytes'}, target size: {'None bytes' if target_size is None else f'{target_size} bytes'})")
                    # Add conditions for other categories (4, 5, 6, 7) here in subsequent steps
                    else: # Fallback for categories not yet handled (e.g., REPORT_DIFFERENT_TYPE, REPORT_COMPARE_ERROR)
                        print(f"      {item_tuple}") # 
        #else:
        #    print("  - No items found in this category.")

        print() # Add blank line between categories

    print(f"\nTotal CPU elapsed wall clock time: {elapsed_time_cpu:.2f} seconds") #
    print("\n" + "="*80)
    print("-------------------------------- End of Report ---------------------------------") #
    print("="*80)
