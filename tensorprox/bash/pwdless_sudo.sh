#!/bin/bash

ssh_user="$1"

echo "${ssh_user} ALL=(ALL) NOPASSWD: ALL" > "/etc/sudoers.d/99_${ssh_user}_temp"
chmod 440 "/etc/sudoers.d/99_${ssh_user}_temp"
