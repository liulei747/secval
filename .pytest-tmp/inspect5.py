import sqlite3
con = sqlite3.connect('/audit-data/sources.sqlite3')
last = con.execute('SELECT id FROM source_snapshots ORDER BY captured_at DESC LIMIT 1').fetchone()[0]
rows = con.execute(
    "SELECT path FROM source_files WHERE snapshot_id=? AND (path LIKE '%node_modules/%' OR path LIKE '%/build/%' OR path LIKE '%/dist/%' OR path LIKE '%/target/%') AND (path LIKE '%.js' OR path LIKE '%.java') LIMIT 5",
    (last,),
).fetchall()
print('minified-in-ignored-dirs:', rows)
rows2 = con.execute(
    "SELECT path, LENGTH(content) FROM source_files WHERE snapshot_id=? AND status='captured' AND path LIKE '%.js' ORDER BY LENGTH(content) DESC LIMIT 5",
    (last,),
).fetchall()
print('largest captured js:', rows2)

