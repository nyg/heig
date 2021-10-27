#!/usr/bin/env sh

sqlite3 database.sqlite .dump > dump.sql
sqlite3 database-test.sqlite .dump > dump-test.sql

