BEGIN TRANSACTION;

CREATE TABLE users (
	email TEXT PRIMARY KEY NOT NULL,
	hashed_pw TEXT NOT NULL,
	role TEXT NOT NULL
);

-- Add some default users.
INSERT INTO users VALUES(
	'user@localhost',
	'$argon2id$v=19$m=4096,t=3,p=1$tXoJG9eGHIhBQeNCfHFg7A$yfdnBeO5lRXV8rVFc768JPr8xe8MZfTQh1HxmMYk1ug',
	'user'
);
INSERT INTO users VALUES(
	'admin@localhost',
	'$argon2id$v=19$m=4096,t=3,p=1$zW6Nsm7QNPDql8seEp1gEQ$lvt1LxV2rFqPsXLke9k9pDOlMxEyyXrPNL63ud0B3MQ',
	'admin'
);

CREATE TABLE refresh_tokens (
	email TEXT NOT NULL,
	user_agent TEXT NOT NULL,
	expires INTEGER,
	PRIMARY KEY (email, user_agent, expires)
);

COMMIT;
