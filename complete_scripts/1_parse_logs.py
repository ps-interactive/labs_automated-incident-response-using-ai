#!/usr/bin/env python3
import re
import pandas as pd
import numpy as np
from dateutil.parser import parse
import os

def parse_auth_log(file_path):
    # Parse authentication log files into structured data
    # Use regular expression to match auth log entries
    log_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)(?:\[(\d+)\])?:\s+(.*)'
    
    data = []
    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                timestamp, host, program, pid, message = match.groups()
                data.append({
                    'timestamp': timestamp,
                    'host': host,
                    'program': program,
                    'pid': pid if pid else '',
                    'message': message
                })
    
    return pd.DataFrame(data)

if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)

    # Parse both log files
    normal_logs = parse_auth_log('auth_logs.txt')
    suspicious_logs = parse_auth_log('auth_logs_suspect.txt')
    
    # Add a label column to mark normal vs suspicious
    normal_logs['label'] = 0  # Normal
    suspicious_logs['label'] = 1  # Suspicious
    
    # Combine the datasets
    all_logs = pd.concat([normal_logs, suspicious_logs], ignore_index=True)
    
    # Save processed data
    all_logs.to_csv('logs/processed_logs.csv', index=False)
    print(f"Processed {len(all_logs)} log entries. Saved to logs/processed_logs.csv")
    
    # Save separate files for easy reference
    normal_logs.to_csv('logs/normal_logs.csv', index=False)
    suspicious_logs.to_csv('logs/suspicious_logs.csv', index=False)
    
    print(f"Normal logs: {len(normal_logs)} entries")
    print(f"Suspicious logs: {len(suspicious_logs)} entries")