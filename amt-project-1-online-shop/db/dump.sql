PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE user
(
	id integer not null
		constraint user_pk
			primary key autoincrement,
	username text not null
, firstname text, lastname text, email text, password text, admin integer default 0);
CREATE TABLE article
(
	id integer
		constraint article_pk
			primary key autoincrement,
	name text not null,
	price numeric not null
, description text);
CREATE TABLE IF NOT EXISTS "cart"
(
	user integer
		references user,
	article integer
		references article, quantity integer default 1 not null,
	constraint cart_pk
		primary key (user, article)
);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('user',59);
CREATE UNIQUE INDEX user_username_uindex
	on user (username);
COMMIT;
