PRETTY=${PRETTY:-1}

log() {
    local c=$1
    shift
    if [ z"$PRETTY" == z0 ]; then
        echo "$@";
    else
        echo -e "\x1b[${c}m\x1b[1m${@}\x1b[0m";
    fi
}

log_info() {
    # Blue
    log 34 $@
}

log_success() {
    # Green
    log 32 $@
}

log_notice() {
    # Yello
    log 33 $@
}

log_error() {
    # Red
    log 31 $@
}

log_test_pass() {
    log_success "[+]" $@
}

log_test_fail() {
    log_error "[-]" $@
}

log_test_skip() {
    log_notice "[.]" $@
}

log_test_suite() {
    log_notice "[#]" $@
}

log_if_else() {
    local pred=$1
    local f1=$2
    local f2=$3
    shift 3
    if [ $pred -eq 0 ]; then
        $f1 $@
    else
        $f2 $@
    fi
}

expect_has() {
    grep -E -q "$1"
}

expect_no() {
    ! grep -E -q "$1"
}

trap_err() {
    log_error Error on line $1
    exit 1
}
