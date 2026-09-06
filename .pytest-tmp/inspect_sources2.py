import sqlite3

con = sqlite3.connect('/audit-data/sources.sqlite3')
last = con.execute('SELECT id FROM source_snapshots ORDER BY captured_at DESC LIMIT 1').fetchone()[0]
rows = con.execute(
    "SELECT path FROM source_files WHERE snapshot_id=? AND status=? "
    "AND (path LIKE '%.java' OR path LIKE '%.js' OR path LIKE '%.ts' OR path LIKE '%.py') LIMIT 10",
    (last, 'non_utf8'),
).fetchall()
print('supported-non-utf8:', rows)
