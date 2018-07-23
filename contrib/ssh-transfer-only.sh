#!/usr/bin/env bash

# Only allow ssh commands starting with 'scp' or 'rsync'
case $SSH_ORIGINAL_COMMAND in
    scp*)
        $SSH_ORIGINAL_COMMAND ;;
    rsync*)
        $SSH_ORIGINAL_COMMAND ;;
    *)
        echo "Not allowed with this key: $SSH_ORIGINAL_COMMAND" ;;
esac
