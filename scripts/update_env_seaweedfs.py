with open('.env', 'r', encoding='utf-8') as f:
    c = f.read()

target = 'EVIDENCE_STORAGE_PATH="./evidence_storage"'
replacement = '''STORAGE_BACKEND="seaweedfs"
SEAWEEDFS_FILER_URL="http://localhost:18888"
SEAWEEDFS_COLLECTION="evidence"
SEAWEEDFS_FALLBACK_TO_FILESYSTEM=true
EVIDENCE_STORAGE_PATH="./evidence_storage"'''

if target in c:
    c = c.replace(target, replacement, 1)
    with open('.env', 'w', encoding='utf-8') as f:
        f.write(c)
    print("Updated .env successfully")
else:
    print("Already updated or target not found")

