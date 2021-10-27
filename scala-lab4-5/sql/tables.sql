/*USE BotTender;*/

DROP TABLE IF EXISTS "message";
DROP TABLE IF EXISTS "account";
DROP TABLE IF EXISTS "exprtype";

CREATE TABLE IF NOT EXISTS "account" (
    userid SERIAL PRIMARY KEY,
    username VARCHAR NOT NULL UNIQUE,
    balance REAL NOT NULL,
    active BOOLEAN NOT NULL  -- indicates if a user can login
);

CREATE TABLE IF NOT EXISTS "exprtype" (
    exprtypeid SERIAL PRIMARY KEY,
    name VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS "message" (
    messageid SERIAL PRIMARY KEY,
    userId INTEGER NOT NULL REFERENCES "account"(userid),
    content TEXT NOT NULL,
    createddate TIMESTAMP NOT NULL DEFAULT now(),
    exprtypeid INTEGER REFERENCES "exprtype"(exprtypeid),
    replytoid INTEGER REFERENCES "message"(messageid),
    mentionid INTEGER REFERENCES "account"(userid)
);

INSERT INTO "account" (username, balance, active) VALUES ('BotTender', 0, FALSE);

INSERT INTO "exprtype" VALUES
    (1, 'Identification'),
    (2, 'QueryCommands'),
    (3, 'OrderCommands'),
    (4, 'SoldQuery'),
    (5, 'Thirsty'),
    (6, 'Hungry'),
    (7, 'Unknown');
