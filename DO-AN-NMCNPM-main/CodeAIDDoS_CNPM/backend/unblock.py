import paramiko
import sys

def unblock_ip_pfsense(host, username, password, interface, ip_to_block):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh_client.connect(hostname=host, username=username, password=password)

        command = f"easyrule unblock {interface} {ip_to_block}"

        stdin, stdout, stderr = ssh_client.exec_command(command)

        output = stdout.read().decode()
        error = stderr.read().decode()

        if output:
            print("Result:", output)
        if error:
            print("Error:", error)

        ssh_client.close()
        print(f"Blocked IP {ip_to_block} on interface {interface} successfully.")

    except Exception as e:
        print(f"Error when execute: {str(e)}")
    

if __name__ == "__main__":

    if len(sys.argv) != 2:
        sys.exit(1)

    ip_to_block = sys.argv[1] 
    pfsense_host = "192.168.1.1"  
    username = "admin"             
    password = "123456"    
    interface = "wan"  

    unblock_ip_pfsense(pfsense_host, username, password, interface, ip_to_block)
    
