export PATH=$PATH:/bin:/usr/sbin:~/.local/bin

alias pupysh=/opt/pupy/pupysh.py
alias pupygen=/opt/pupy/pupygen.py
alias gen=/opt/pupy/pupygen.py

project=default

if [ -f /home/pupy/.project ]; then
    project=`cat /home/pupy/.project`
fi

case $- in *i*)
   if [ -z "$TMUX" ] && [ ! -z "$SSH_CLIENT" ]; then
        echo -ne "\033]0;[ PUPY:${project} ]\007"
        ( tmux -2 attach || tmux -2 new-session \
				 -c "/projects/${project}" \
				 -s pupy \
				 -n "${project}" /opt/pupy/pupysh.py )
        [ $? -eq 0 ] && exit 0
   fi
esac
