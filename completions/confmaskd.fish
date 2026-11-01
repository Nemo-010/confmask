# fish completion for confmaskd.

complete -c confmaskd -s S -l socket -d 'Socket path' -r
complete -c confmaskd -s l -l label -d 'Default label' -x
complete -c confmaskd -s e -l env-file -d 'Environment file' -r
complete -c confmaskd -l no-inherit-env -d 'Jobs get the env-file only'
complete -c confmaskd -l keep-env -d 'Leave environ visible'
complete -c confmaskd -l allow-uid -d 'Accept this uid' -x
complete -c confmaskd -l run-as-uid -d 'Run jobs with the client uid'
complete -c confmaskd -l socket-mode -d 'Socket permission bits' -x
complete -c confmaskd -l io-timeout -d 'Drop a stalled client' -x
complete -c confmaskd -l job-timeout -d 'Kill a job after this long' -x
complete -c confmaskd -l jobs -d 'Run up to N jobs at once' -x
complete -c confmaskd -l max-job-bytes -d 'Largest job argument bytes' -x
complete -c confmaskd -s q -l quiet -d 'Suppress diagnostics'
complete -c confmaskd -s v -l verbose -d 'Log each job'
complete -c confmaskd -s V -l version -d 'Print version'
complete -c confmaskd -s h -l help -d 'Print help'
