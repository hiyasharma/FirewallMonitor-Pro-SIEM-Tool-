import os
import time

def monitor_firewall_log(log_file_path):
    try:
        if not os.path.exists(log_file_path):
            print(f"Error: Log file '{log_file_path}' not found.")
            return

        print(f"Monitoring firewall log file: {log_file_path}")


        # Get initial file size
        current_file_size = os.path.getsize(log_file_path)

        while True:
            # Get current file size
            new_file_size = os.path.getsize(log_file_path)

            # Check if the file size has increased (new entries added)
            if new_file_size > current_file_size:
                print("New entries detected!")

                # Open the log file and read new entries
                with open(log_file_path, 'r') as log_file:
                    log_file.seek(current_file_size)  # Move to the last read position
                    new_entries = log_file.read(new_file_size - current_file_size)

                    # Display new entries
                    print("New Entries:")
                    print(new_entries)

                # Update current file size
                current_file_size = new_file_size

            # Sleep for a short interval (e.g., 5 seconds) before checking again
            time.sleep(5)

    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")

if __name__ == "__main__":
    log_file_path = r'C:\Users\hiyas\OneDrive\Desktop\pfirewall.log1.txt'
    monitor_firewall_log(log_file_path)

    
