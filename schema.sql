CREATE TABLE IF NOT EXISTS keys (
  key_id TEXT PRIMARY KEY,
  role TEXT DEFAULT 'trial',
  created_at INTEGER DEFAULT 0,
  expires_at INTEGER DEFAULT 0,
  duration_label TEXT DEFAULT '',
  note TEXT DEFAULT '',
  disabled INTEGER DEFAULT 0,
  devices TEXT DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_keys_created ON keys(created_at);

CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY,
  type TEXT DEFAULT 'movie',
  title TEXT DEFAULT '',
  poster TEXT DEFAULT '',
  slide_image TEXT DEFAULT '',
  note TEXT DEFAULT '',
  created_at INTEGER DEFAULT 0,
  video_url TEXT DEFAULT '',
  download_url TEXT DEFAULT '',
  seasons TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_items_type ON items(type);
CREATE INDEX IF NOT EXISTS idx_items_created ON items(created_at);

CREATE TABLE IF NOT EXISTS sessions (
  key_id TEXT NOT NULL,
  sid TEXT NOT NULL,
  created_at INTEGER DEFAULT 0,
  meta TEXT DEFAULT '{}',
  expires_at INTEGER DEFAULT 0,
  PRIMARY KEY (key_id, sid)
);

CREATE TABLE IF NOT EXISTS kdev (
  device_id TEXT PRIMARY KEY,
  key_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
  rl_key TEXT PRIMARY KEY,
  count INTEGER DEFAULT 0,
  reset_at INTEGER DEFAULT 0
);
