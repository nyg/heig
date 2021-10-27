#!/usr/bin/env sh

rm database.sqlite 2>/dev/null
sqlite3 database.sqlite < dump.sql
sqlite3 database-test.sqlite < dump-test.sql