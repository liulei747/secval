import sqlite3
con = sqlite3.connect('/audit-data/sources.sqlite3')
last = con.execute('SELECT id FROM source_snapshots ORDER BY captured_at DESC LIMIT 1').fetchone()[0]
rows = con.execute(
    "SELECT path, status FROM source_files WHERE snapshot_id=? AND status!='captured' AND (path LIKE '%.java' OR path LIKE '%.js' OR path LIKE '%.py' OR path LIKE '%.ts' OR path LIKE '%.tsx' OR path LIKE '%.JS' OR path LIKE '%.Java')",
    (last,),
).fetchall()
print('all non-captured supported:', rows)

