import sqlite3
con = sqlite3.connect('/audit-data/sources.sqlite3')
last = con.execute('SELECT id FROM source_snapshots ORDER BY captured_at DESC LIMIT 1').fetchone()[0]
row = con.execute("SELECT COUNT(*), SUM(LENGTH(content)) FROM source_files WHERE snapshot_id=? AND status='captured'", (last,)).fetchone()
print('captured files:', row)
rows = con.execute(
    "SELECT path, status FROM source_files WHERE snapshot_id=? AND status='non_utf8' AND (path LIKE '%.sql' OR path LIKE '%.xml' OR path LIKE '%.yml' OR path LIKE '%.properties') LIMIT 10",
    (last,),
).fetchall()
print('non-utf8 config-like:', rows)

