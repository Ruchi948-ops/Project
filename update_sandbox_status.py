import pymysql

# DB connection
conn = pymysql.connect(
    host='localhost',
    user='root',  # 👈 Replace with your MySQL username
    password='RUCHI@@123!',  # 👈 Replace with your MySQL password
    database='register'  # 👈 Replace with your DB name (e.g., patch_system)
)

cursor = conn.cursor()

# Simulate sandbox result
patch_name = 'window.sh'  # 👈 Replace with your tested patch name
sandbox_result = 'Passed'  # 👈 Change to 'Failed' if it fails

# Update query
query = "UPDATE patches SET sandbox_status = %s WHERE file_name = %s"
cursor.execute(query, (sandbox_result, patch_name))

conn.commit()
print("✅ Sandbox result updated in MySQL.")

cursor.close()
conn.close()
