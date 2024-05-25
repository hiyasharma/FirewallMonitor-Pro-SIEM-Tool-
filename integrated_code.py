import os
import time

def parse_firewall_log_entry(log_entry):
    # Function to parse a single firewall log entry into a dictionary of fields
    fields = [
        'Date', 'Time', 'Action', 'Protocol', 'SourceIP', 'DestinationIP',
        'SourcePort', 'DestinationPort', 'Size', 'TCPFlags', 'TCPSYN', 'TCPACK',
        'TCPWin', 'ICMPType', 'ICMPCode'
    ]
    try:
        parsed_entry = dict(zip(fields, log_entry.split('\t')))
    except Exception as e:
        print(f"Error parsing log entry: {log_entry}")
        raise  # Reraise the exception for detailed traceback
    return parsed_entry

def is_suspicious_entry(log_entry):
    # Function to determine if a firewall log entry is suspicious
    # Example criteria: Action is 'Block' and Protocol is 'UDP'
    return log_entry.get('Action') == 'Block' and log_entry.get('Protocol') == 'UDP'

def generate_alert(log_entry):
    # Function to generate alerts for suspicious firewall log entries
    source_ip = log_entry['SourceIP']
    destination_ip = log_entry['DestinationIP']
    print(f"ALERT: Detected suspicious traffic from {source_ip} to {destination_ip}")

def monitor_firewall_log(log_file_path):
    try:
        if not os.path.exists(log_file_path):
            print(f"Error: Log file '{log_file_path}' not found.")
            return

        print(f"Monitoring firewall log file: {log_file_path}")

        # Display existing logs
        print("Existing Logs:")
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                try:
                    parsed_entry = parse_firewall_log_entry(line.strip())
                    print(parsed_entry)
                except Exception as e:
                    print(f"Error processing log entry: {line.strip()} - {e}")

        # Get initial file size
        current_file_size = os.path.getsize(log_file_path)

        # Infinite loop for continuous monitoring
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

                    # Split new entries into lines and parse each log entry
                    for line in new_entries.splitlines():
                        try:
                            parsed_entry = parse_firewall_log_entry(line)
                            if is_suspicious_entry(parsed_entry):
                                generate_alert(parsed_entry)  # Generate alert for suspicious entry
                            else:
                                print("New Entry:")
                                print(line)
                        except Exception as e:
                            print(f"Error processing log entry: {line.strip()} - {e}")

                # Update current file size
                current_file_size = new_file_size

            # Sleep for a short interval (e.g., 5 seconds) before checking again
            time.sleep(5)

    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")

if __name__ == "__main__":
    log_file_path = r'C:\Users\hiyas\OneDrive\Desktop\pfirewall.log1.txt'
    monitor_firewall_log(log_file_path)
