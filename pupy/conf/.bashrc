export PATH=$PATH:~/.local/bin

alias pupysh=/opt/pupy/pupysh.py
alias pupygen=/opt/pupy/pupygen.py
alias gen=/opt/pupy/pupygen.py

case $- in *i*)
   if [ -z "$TMUX" ]; then
        echo "Starting tmux.."
        echo -ne "\033]0;[ PUPY ]\007"
        ( tmux -2 attach || tmux -2 new-session \
				 -c '/home/pupy/projects/default' \
				 -s pupy \
				 -n 'default' /opt/pupy/pupysh.py )
        [ $? -eq 0 ] && exit 0
   fi
esac
