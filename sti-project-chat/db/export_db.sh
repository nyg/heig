#!/usr/bin/env sh

sqlite3 database.sqlite .dump > dump.sql
