import paramiko
import os

# Function to execute the patch on remote system
def execute_patch(remote_host, username, password, patch_path, os_type=None):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh_client.connect(remote_host, username=username, password=password)

        # Ensure the patch file exists at the specified location
        stdin, stdout, stderr = ssh_client.exec_command(f"ls {patch_path}")
        file_check = stdout.read().decode()
        if "No such file" in file_check:
            print(f"Patch file {patch_path} not found!")
            return False

        # Execute the patch based on OS type
        if os_type == 'linux':
            print(f"Running command: sh {patch_path}")
            stdin, stdout, stderr = ssh_client.exec_command(f"sh {patch_path}")
        elif os_type == "pfsense":
            print(f"Running command: pfSsh.php playback patch_apply {patch_path}")
            stdin, stdout, stderr = ssh_client.exec_command(f"pfSsh.php playback patch_apply {patch_path}")
        else:
            print(f"Running command for unknown OS: {patch_path}")
            stdin, stdout, stderr = ssh_client.exec_command(f"sh {patch_path}")

        output = stdout.read().decode()
        error = stderr.read().decode()

        print(f"🔹 STDOUT: {output}")
        print(f"🔸 STDERR: {error}")

        if error:
            print(f"Execution Error: {error}")
            return False

        print(f"Patch Execution Output: {output}")
        return True

    except Exception as e:
        print(f"Error executing patch: {e}")
        return False
    finally:
        ssh_client.close()


# Function to upload patch to a remote system
def upload_patch_to_remote(file_path, remote_host, username, password, remote_path="/tmp/"):
    """Uploads a patch file to a remote machine based on OS type"""
    try:
        print(f"Uploading {file_path} to {remote_host}...")

        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(remote_host, username=username, password=password)

        # Open SFTP connection
        sftp = ssh_client.open_sftp()
        remote_file_path = os.path.join(remote_path, os.path.basename(file_path))
        print(f"🔹 Uploading to: {remote_file_path}")
        sftp.put(file_path, remote_file_path)
        sftp.close()

        print(f"Patch uploaded successfully to: {remote_file_path}")
        return remote_file_path  # Return the uploaded path

    except Exception as e:
        print(f"Upload failed: {e}")
        return None
    finally:
        ssh_client.close()
