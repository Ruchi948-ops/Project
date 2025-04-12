import paramiko
import os
import logging

logging.basicConfig(filename="patch_logs.log", level=logging.INFO, format="%(asctime)s - %(message)s")

WINDOWS_IP = "172.31.173.151"  # Change this to your Windows IP
WINDOWS_USER = "WDAGUtilityAccount"
WINDOWS_PASSWORD = "password"

def log_patch_activity(action, patch_name, status):
    logging.info(f"{action}: {patch_name} - Status: {status}")

def upload_patch(patch_file):
    try:
        print(f"Uploading {patch_file} to Windows...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(WINDOWS_IP, username=WINDOWS_USER, password=WINDOWS_PASSWORD)

        scp = ssh.open_sftp()
        dest_path = f"C:\\path\\to\\patches\\{os.path.basename(patch_file)}"
        scp.put(patch_file, dest_path)
        scp.close()

        print(f"Upload successful: {dest_path}")
        log_patch_activity("UPLOAD", patch_file, "SUCCESS")

        ssh.close()
        return dest_path
    except Exception as e:
        print(f"Upload failed: {e}")
        log_patch_activity("UPLOAD", patch_file, f"FAILED - {e}")
        return None

def apply_patch(patch_path):
    try:
        print(f"Applying patch: {patch_path} on Windows...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(WINDOWS_IP, username=WINDOWS_USER, password=WINDOWS_PASSWORD)

        command = f"cmd.exe /c {patch_path}"  # Use appropriate command for Windows
        stdin, stdout, stderr = ssh.exec_command(command)

        output = stdout.read().decode()
        error = stderr.read().decode()

        print(f"Patch applied successfully on Windows!\nOutput: {output}")
        if error:
            print(f"Errors: {error}")

        ssh.close()
        return True  # Return True for successful patch application
    except Exception as e:
        print(f"Patch execution failed: {e}")
        return False  # Return False for failure

def rollback_patch(patch_path):
    """Rolls back the last applied patch (for Windows)."""
    try:
        print(f"Rolling back patch: {patch_path}")

        # Initialize SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(WINDOWS_IP, username=WINDOWS_USER, password=WINDOWS_PASSWORD)

        # Execute rollback command (customize this based on your rollback process)
        command = f"cmd.exe /c {patch_path} --rollback"
        stdin, stdout, stderr = ssh.exec_command(command)

        output = stdout.read().decode()
        error = stderr.read().decode()

        print(f"Rollback successful!\nOutput: {output}")
        if error:
            print(f"Errors: {error}")

        log_patch_activity("ROLLBACK", patch_path, "SUCCESS" if not error else f"WARNING - {error}")

        ssh.close()

    except Exception as e:
        print(f"Rollback failed: {e}")
        log_patch_activity("ROLLBACK", patch_path, f"FAILED - {e}")

# User Interface for Execution
if __name__ == "__main__":
    print("Windows Patch Management System")
    print("1️⃣ Upload Patch")
    print("2️⃣ Apply Patch")
    print("3️⃣ Rollback Patch")
    choice = input("Select an option (1-3): ")

    if choice == "1":
        patch_file = input("Enter the path of the patch file to upload: ").strip()
        if os.path.exists(patch_file):
            upload_patch(patch_file)
        else:
            print("File not found!")

    elif choice == "2":
        patch_path = input("Enter the patch path on Windows to apply: ").strip()
        apply_patch(patch_path)

    elif choice == "3":
        patch_path = input("Enter the patch path on Windows to rollback: ").strip()
        rollback_patch(patch_path)

    else:
        print("Invalid choice!")
