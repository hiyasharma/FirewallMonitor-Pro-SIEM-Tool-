def parse_firewall_logs(log_file_path):
    log_entries = []

    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                if line.startswith('#'):
                    continue  

                fields = line.strip().split('\t')

                if len(fields) >= 15:
                    log_entry = {
                        'Date': fields[0],
                        'Time': fields[1],
                        'Action': fields[2],
                        'Protocol': fields[3],
                        'SourceIP': fields[4],
                        'DestinationIP': fields[5],
                        'SourcePort': fields[6],
                        'DestinationPort': fields[7],
                        'Size': fields[8],
                        'TCPFlags': fields[9],
                        'TCPSYN': fields[10],
                        'TCPACK': fields[11],
                        'TCPWin': fields[12],
                        'ICMPType': fields[13],
                        'ICMPCode': fields[14]
                    }
                    log_entries.append(log_entry)

    except FileNotFoundError:
        print(f"Log file '{log_file_path}' not found.")

    return log_entries


desktop_path = "C:\\Users\\hiyas\\OneDrive\\Desktop\\"  # Update with your desktop path
firewall_log_path = desktop_path + "pfirewall.log1.txt"

parsed_logs = parse_firewall_logs(firewall_log_path)

for log in parsed_logs:
    print(log)
