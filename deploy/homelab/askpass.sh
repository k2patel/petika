#!/bin/sh
case "$1" in
  *Username*) printf '%s\n' 'petika-backup';;
  *Password*) cat /backup-auth/token;;
  *) exit 1;;
esac
