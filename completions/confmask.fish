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
complete -c confmask -s q -l quiet -d 'Suppress diagnostics'
complete -c confmask -s v -l verbose -d 'Trace every event'
complete -c confmask -s V -l version -d 'Print version'
complete -c confmask -s h -l help -d 'Print help'
complete -c confmask -s a -d 'Alias for --label' -x
complete -c confmask -s E -d 'Alias for --keep-env'
complete -c confmask -s F -d 'Alias for --no-follow'
complete -c confmask -s K -d 'Alias for --no-exit-kill'
