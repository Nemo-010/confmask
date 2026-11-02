# bash completion for confmask                       -*- shell-script -*-
# Static file: the option parser is hand-written, so the list is too.

_confmask() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="-l --label --label-empty --argv0 --comm --keep-env --env --env-file \
--args-from-fd --on-exit --no-follow --no-exit-kill --no-dumpable \
--no-new-privs --watch-rename --rexec --unshare --scope-name --daemon \
--secret --socket --isolate --no-redact \
-q --quiet -v --verbose -V --version -h --help -a -E -F -K"

    if [ "$COMP_CWORD" -eq 1 ] && [[ "$cur" != -* ]]; then
        COMPREPLY=( $(compgen -W "run store agent get read probe doctor help version" -- "$cur") )
        return 0
    fi

    case "$prev" in
        -l|--label|-a|--argv0|--comm|--scope-name)
            COMPREPLY=( $(compgen -W "ci-runner app-worker" -- "$cur") )
            return 0
            ;;
        --daemon|--env-file|--secret)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        --on-exit)
            COMPREPLY=( $(compgen -W "detach wait kill" -- "$cur") )
            return 0
            ;;
        --env)
            COMPREPLY=( $(compgen -W "PATH= HOME= LANG=" -- "$cur") )
            return 0
            ;;
        --keep-env)
            COMPREPLY=( $(compgen -W "PATH HOME LANG TERM" -- "$cur") )
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
        return 0
    fi
    COMPREPLY=( $(compgen -c -- "$cur") )
}
complete -F _confmask confmask
