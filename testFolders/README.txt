# With Excluding Directories
python3.11 src/main.py --exclude-file testFolders/files2exclude_a.txt --time-tolerance 1 --hash-check -- testFolders/source_dir/ testFolders/target_dir/ > testFolders/hash-check_off_files2exclude_a2.logcd

# Without Excluding Directories
python3.11 src/main.py --time-tolerance 1 --hash-check -- testFolders/source_dir/ testFolders/target_dir/ > testFolders/hash-check_off_files2exclude_a2.logcd
