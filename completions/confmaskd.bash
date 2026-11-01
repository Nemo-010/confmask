# bash completion for confmaskd                      -*- shell-script -*-

_confmaskd() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="-S --socket -l --label -e --env-file --no-inherit-env --keep-env \
--allow-uid --run-as-uid --socket-mode --io-timeout --job-timeout --jobs \
--max-job-bytes -q --quiet -v --verbose -V --version -h --help"

    case "$prev" in
        -S|--socket|-e|--env-file)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        -l|--label)
            COMPREPLY=( $(compgen -W "confmask-job ci-runner" -- "$cur") )
            return 0
            ;;
        --allow-uid|--socket-mode|--io-timeout|--job-timeout|--jobs|--max-job-bytes)
            COMPREPLY=()
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
        return 0
    fi
}
complete -F _confmaskd confmaskd
