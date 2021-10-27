#!/usr/bin/env sh

mkdir -p site/databases
chmod a+w site/databases

rm site/databases/database.sqlite 2>/dev/null
sqlite3 site/databases/database.sqlite < db/dump.sql
chmod a+w site/databases/database.sqlite
