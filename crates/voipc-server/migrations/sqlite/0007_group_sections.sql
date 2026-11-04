-- A group whose people should not stand under it in the member list (1.9).
ALTER TABLE voipc_group_style ADD COLUMN no_section BOOLEAN NOT NULL DEFAULT 0;
