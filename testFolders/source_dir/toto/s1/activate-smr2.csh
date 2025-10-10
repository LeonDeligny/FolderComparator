# csh script to activate Python venv "$1"

# srpm 2022-01-06

set VENV_PATH = "/soft/smr/"
if ( "$#argv" != 1 ) then
    echo "Please specify venv name"
    exit 1
endif

if ( ! -d $VENV_PATH/$1 ) then
   echo "Virtual environment not fount"
   exit 1
endif

if ( ! $?VIRTUAL_ENV ) then
   source $HOME/deactivate-smr.csh
endif

setenv LD_LIBRARY_PATH_OLD $LD_LIBRARY_PATH
setenv PATH_OLD            $PATH
setenv PYTHONPATH_OLD      $PYTHONPATH
setenv SMR_SRC_OLD         $SMR_SRC

source $VENV_PATH/$1/bin/activate.csh

setenv LD_LIBRARY_PATH     $VIRTUAL_ENV/lib64:$VIRTUAL_ENV/lib:/usr/local/lib64
setenv SMR_PREFIX          $VIRTUAL_ENV
setenv VIRTUAL_ENV_NAME    $1
setenv PYTHONPATH          $VIRTUAL_ENV/lib/python`python -c 'import sys; print("%d.%d" % (sys.version_info[0], sys.version_info[1])) ;'`/site-packages

setenv SMR_SRC             $HOME/sources/smr-packages-november-2021
setenv SMR_CMAKEMODULES    $SMR_SRC/CMakeModules
setenv BUILD               /wrk/a/build/smr/$VIRTUAL_ENV_NAME
