-- INFINEX 冊子：初期テーブル
CREATE TABLE IF NOT EXISTS projects (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL DEFAULT '',
  data        TEXT NOT NULL,
  rev         INTEGER NOT NULL DEFAULT 1,
  size        INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  updated_by  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_projects_updated ON projects(updated_at);

-- 画像の本体は KV（FILES）に "a/<sha256>" で保存し、ここには一覧と冊子との対応だけを持つ
CREATE TABLE IF NOT EXISTS assets (
  hash        TEXT PRIMARY KEY,
  mime        TEXT NOT NULL,
  size        INTEGER NOT NULL,
  created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS asset_refs (
  project_id  TEXT NOT NULL,
  hash        TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  PRIMARY KEY (project_id, hash)
);
CREATE INDEX IF NOT EXISTS idx_asset_refs_hash ON asset_refs(hash);

CREATE TABLE IF NOT EXISTS login_attempts (
  ip     TEXT PRIMARY KEY,
  fails  INTEGER NOT NULL,
  until  INTEGER NOT NULL
);
