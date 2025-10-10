if ( -o /dev/$tty && ${?prompt} ) then
   echo " --> executing ~"$user"/.alias.csh"
endif

alias	cls		"clear"
alias	rm		"rm -iv"
#alias	rm		"set noglob ; rmsecure -i \!* ; unset noglob"
alias	mv		"mv -iv"
alias	cp		"cp -iv"
alias	p		"ps -u $user"
alias	lo		"logout"
alias	vt330		"stty erase '^?'"
#alias	ls 		"ls $LS_OPTIONS"
alias	ll		"ls -Flh    \!*"
alias	la		"ls -FAlh   \!*"
alias	lt		"ls -FAlrth \!*"
alias	lall		"ls -FAlRh  \!*"
alias	llink		"ls -Flh    \!* | grep ^l"
alias	findSymLink	"find \!* -type l -exec ls -l {} \;"
alias	clearbuf	'echo "\033[14/y\c"'
alias	bip		'echo "\007\c"'
alias	r1		"chmod 400"
alias	r2		"chmod 440"
alias	w1		"chmod 600"
alias	w2		"chmod 660"
alias	x1		"chmod 500"
alias	x2		"chmod 550"
alias	gdiff		"mgdiff -quit -args -bwi"
alias	lpcs		"lp -dcolor-simplex"
alias	lpc		"lp -dcolor"
alias	lps		"lp -dsimplex"
alias	lpd		"lp"
alias	ssg		"ssh -XY gehri@cfs\!:1"
alias   cfs1   		"ssh -X gehri@cfs1.cfse.ch"
alias	cfs		"ssh -XYo ProxyCommand='ssh -XYW %h:%p gehri@cfs1.cfse.ch' -L 3390:localhost:3390 gehri@cfs\!:1"
alias	png2mp4		"ffmpeg -r 25 -pattern_type glob -i '*.png' -c:v libx264 -profile:v baseline -pix_fmt yuv420p out.mp4"
alias	flc2png		"mplayer -vo png \!:1"
alias	fcache		"ssh root@$HOST '/bin/sync; /sbin/sysctl -w vm.drop_caches=3; /sbin/sysctl -w vm.drop_caches=0'"
alias	tosmr		"scp -rp \!* gtjd_gehri@gtjd.ftp.infomaniak.com:smr"
alias	dropbox_start	"~/.dropbox-dist/dropboxd &"
alias pbaspl		"podman start -ai baspl-2.4.23"

# The first parameter is the name of the path-variable to be modified.
# The second parameter is the path-element to replace.
# The third parameter is the new path-element (or "" to simply remove the path-element matching the 2nd parameter).
#http://stackoverflow.com/questions/11119203/how-to-remove-a-path-from-ld-library-path-in-tcsh
alias	repath 'setenv \!:1 `echo $\!:1\: | perl -pe "s[^\!:2\:][\!:3\:]g; s[\:\!:2\:][\:\!:3\:]g; s[\:\:][\:]g; s[^\:][]g;"`'

# This pstopdf alias converts a vector postscript file into a vector pdf file,
# without all these arguments the pdf file is no longer a vector graphic
alias   pstopdf		"ps2pdf -dMaxSubsetPct=100 -dCompatibilityLevel=1.3 -dSubsetFonts=true -dEmbedAllFonts=true -dAutoFilterColorImages=false -dAutoFilterGrayImages=false -dColorImageFilter=/FlateEncode -dGrayImageFilter=/FlateEncode -dMonoImageFilter=/FlateEncode"

# Concatenate pdf files
alias	pdf2pdf		"gs -q -sPAPERSIZE=a4 -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile=out.pdf"

# tcsh help system does search for uncompressed helps file
# within the cat directory system of a old manual page system.
# Therefore we use whatis as alias for this helpcommand
alias	helpcommand	"whatis"

# StarCCM on cfs8
alias star "/wrk/charbonnier/SOFT/Siemens/12.06.011/STAR-CCM+12.06.011/star/bin/starccm+"

#alias syncOwncloud "owncloudcmd -u gehri -p Bangon721025 /home/gehri/nextcloud https://www.cfse.ch/nextcloud"

alias activate-smr-p2 "source $HOME/virtualenv/activate-smr-p2.csh almalinux8-p2"
alias activate-smr-p3 "source $HOME/virtualenv/activate-smr-p3.csh almalinux8-p3"
alias deactivate-smr  "source $HOME/virtualenv/deactivate-smr.csh"
alias activate-p3     "source $HOME/virtualenv/venv_p3/bin/activate.csh"
alias deactivate-p3   "deactivate"
