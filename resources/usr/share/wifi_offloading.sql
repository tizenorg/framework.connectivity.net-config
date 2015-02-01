PRAGMA journal_mode = PERSIST;

DROP TABLE IF EXISTS "connected_wifi";
CREATE TABLE connected_wifi(
	wifi_id	INTEGER PRIMARY KEY,
	ssid TEXT
);

DROP TABLE IF EXISTS "related_cell";
CREATE TABLE related_cell(
	cell_id INTEGER,
	registered INTEGER,
	max_rscp INTEGER,
	min_rscp INTEGER,
	wifi_id INTEGER
);

CREATE INDEX related_cell_ix_1 ON related_cell (wifi_id);
