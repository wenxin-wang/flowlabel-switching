#!/bin/bash

set -a

__DIR__=$(cd ${BASH_SOURCE[0]%/*} && pwd)
__SRC__=$(cd $__DIR__/.. && pwd)
__TOOLS__=$__SRC__/tools
__BPF__=$__SRC__/bpf
__TEST__=$__SRC__/test
__BPFFS_PATH__=/run/flsw/bpf
. $__TEST__/common.sh

set +a

NOPOST=${NOPOST:-0}

export PATH=$PATH:$__SRC__/tools/

run_test() {
    local script=$1
    if [ -x $script ]; then
        $script
        ret=$?
        name=${script##*/}
        if [ $ret -eq 0 ]; then
            log_test_pass $name
            passed=$((passed+1))
        elif [ $ret -eq 1 ]; then
            log_test_fail $name
            failed=$((failed+1))
        elif [ $ret -eq 2 ]; then
            log_test_skip $name
            skipped=$((skipped+1))
        else
            log_test_fail $name strange return code $ret
            errors=$((errors+1))
        fi
    fi
}

run_post() {
    local dir=$1
    if [ z"$NOPOST" = z1 ]; then
	return
    fi
    if [ -f $dir/post ] && [ -x $dir/post ]; then
        if ! $dir/post; then
            log_error $dir/post failed
            exit 1
        fi
    fi
}

run_pre() {
    local dir=$1
    if [ -x $dir/pre ]; then
        if ! $dir/pre; then
            log_error $dir/pre failed
            run_post $dir
            exit 1
        fi
    fi
}

run_suite() {
    local dir=$1
    shift
    suite=$(basename $dir)
    log_test_suite $suite running
    run_pre $dir
    local passed=0
    local failed=0
    local skipped=0
    local errors=0
    local test_list
    if [ $# -eq 0 ]; then
        test_list="$dir/test_*"
    else
        test_list="$@"
    fi
    for script in $test_list; do
        run_test $script
    done
    run_post $dir
    log_info "PASSED: $passed"
    log_if_else $failed log_info log_error "FAILED: $failed"
    log_if_else $skipped log_info log_notice "SKIPPED: $skipped"
    log_if_else $errors log_info log_error "ERRORS: $errors"
    log_test_suite $suite done
}

if [ $# -eq 0 ]; then
    echo $__TESTS__
    for dir in $__TEST__/test_*; do
        if [ ! -d $dir ]; then
            continue
        fi
        export SUITE=$dir
        run_suite $dir
    done
else
    for t in $@; do
        if [ -d $t ]; then
            export SUITE=$(cd $t && pwd)
            run_suite $SUITE
        elif [ -x $t ]; then
            export SUITE=$(cd $(dirname $t) && pwd)
            run_suite $SUITE $t
        fi
    done
fi
