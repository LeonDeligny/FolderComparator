cd /home/gehri/sources/tools/python_scripts/folder_comparator/testFolders

Using files2exclude_a.txt
-------------------------
python3.11 ../../folder_comparator.py --exclude-file files2exclude_a.txt --time-tolerance 1              -- source_dir/ target_dir/ > hash-check_off_files2exclude_a.log
python3.11 ../../folder_comparator.py --exclude-file files2exclude_a.txt --time-tolerance 1 --hash-check -- source_dir/ target_dir/ > hash-check_md5_files2exclude_a.log

Using files2exclude_b.txt
-------------------------
python3.11 ../../folder_comparator.py --exclude-file files2exclude_b.txt --time-tolerance 1              -- source_dir/toto/ target_dir/toto/ > hash-check_off_files2exclude_b.log
python3.11 ../../folder_comparator.py --exclude-file files2exclude_b.txt --time-tolerance 1 --hash-check -- source_dir/toto/ target_dir/toto/ > hash-check_md5_files2exclude_b.log
