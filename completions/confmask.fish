# fish completion for confmask.  Static file for the hand-written parser.

complete -c confmask -s l -l label -d 'Presentation label' -x
complete -c confmask -l label-empty -d 'Empty label'
complete -c confmask -l argv0 -d 'argv[0] of the program' -x
complete -c confmask -l comm -d 'Process name for top' -x
complete -c confmask -l keep-env -d 'Leave environ visible'
complete -c confmask -l env -d 'Add or replace one variable' -x
complete -c confmask -l env-file -d 'Read variables from a file' -r
complete -c confmask -l args-from-fd -d 'Read the command from a descriptor' -x
complete -c confmask -l on-exit -d 'Descendant policy' -x -a 'detach wait kill'
complete -c confmask -l no-follow -d 'Redact only the direct child'
complete -c confmask -l no-exit-kill -d 'Do not set PTRACE_O_EXITKILL'
complete -c confmask -l no-dumpable -d 'Set PR_SET_DUMPABLE=0'
complete -c confmask -l no-new-privs -d 'Set no_new_privs'
complete -c confmask -l watch-rename -d 'Revert later renames to the label'
complete -c confmask -l rexec -d 'Exec from a sealed memfd'
complete -c confmask -l unshare -d 'New user, pid and mount namespaces'
complete -c confmask -l scope-name -d 'systemd transient scope name' -x
complete -c confmask -l daemon -d 'Run the job in a confmaskd' -r
complete -c confmask -l secret -d 'Deliver a secret on a descriptor: N=SRC' -x
complete -c confmask -l socket -d 'Secret-agent socket for agent: sources' -r
complete -c confmask -l isolate -d 'Fresh namespaces: pid,net,tmp | all | none' -x -a 'pid,net,tmp all none'
complete -c confmask -l no-redact -d 'Never touch /proc metadata'
complete -c confmask -s q -l quiet -d 'Suppress diagnostics'
complete -c confmask -s v -l verbose -d 'Trace every event'
complete -c confmask -s V -l version -d 'Print version'
complete -c confmask -s h -l help -d 'Print help'
complete -c confmask -s a -d 'Alias for --label' -x
complete -c confmask -s E -d 'Alias for --keep-env'
complete -c confmask -s F -d 'Alias for --no-follow'
complete -c confmask -s K -d 'Alias for --no-exit-kill'
complete -c confmask -f -n '__fish_seen_subcommand_from confmask; test (count (commandline -opc)) -le 1' -a 'run\t"Run a command (same parser as the default mode)" store\t"The encrypted secret store" agent\t"Hold the store unlocked and serve it" get\t"Ask a running agent for one secret" read\t"Print a secret delivered to this process" probe\t"What this host allows" doctor\t"Store, agent and verdict in one report" help\t"Print help" version\t"Print version"'
