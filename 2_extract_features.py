#!/usr/bin/env python3
import pandas as pd
import numpy as np
import re
import os

def extract_features(df):
    # Extract meaningful features from log entries for ML processing
    # Extract time
    df['datetime'] = pd.to_datetime(df['timestamp'], format='%b %d %H:%M:%S', errors='coerce')
    df['hour'] = df['datetime'].dt.hour

    # Extract failed password attempts
    df['failed_password'] = df['message'].str.contains('Failed password', case=False).astype(int)

    # Extract successful login attempts
    df['accepted_login'] = df['message'].str.contains('Accepted', case=False).astype(int)

    # IP address extraction
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    df['has_ip'] = df['message'].str.contains(ip_pattern).astype(int)

    # Extract root access attempts
    df['root_access'] = df['message'].str.contains('root', case=False).astype(int)

    # Extract user addition or modification
    df['user_mod'] = df['message'].str.contains('user|useradd|usermod|password changed', case=False).astype(int)

    # Extract sudo commands
    df['sudo_cmd'] = df['message'].str.contains('sudo', case=False).astype(int)

    # Extract Invalid user attempts
    df['invalid_user'] = df['message'].str.contains('invalid user', case=False).astype(int)

    # Extract system commands (wget, bash, etc.)
    df['system_cmd'] = df['message'].str.contains('/bin/|/usr/bin/|wget|curl|bash', case=False).astype(int)

    

    # Extact log manipulation attempts
    df['log_manipulation'] = df['message'].str.contains('rm -rf|sed -i|/var/log', case=False).astype(int)

    # Backdoor related
    df['backdoor'] = df['message'].str.contains('backdoor', case=False).astype(int)

    # Count of consecutive failed attempts from same IP
    # This requires grouping by IP and checking sequences, which is complex for this simple feature extraction
    # We'll use program type instead as a proxy

    # Generate program type
    program_dummies = pd.get_dummies(df['program'], prefix='program')

    # Combine all features
    features = pd.concat([
        df[['hour', 'failed_password', 'accepted_login', 'has_ip', 'root_access',
            'user_mod', 'sudo_cmd', 'invalid_user', 'system_cmd', 'suspicious_tool',
            'log_manipulation', 'backdoor']],
        program_dummies
    ], axis=1)

    return features

if __name__ == "__main__":
    # Create model directory if it doesn't exist
    os.makedirs("model", exist_ok=True)

    # Load processed logs
    logs_df = pd.read_csv('logs/processed_logs.csv')

    # Extract features
    features_df = extract_features(logs_df)

    # Add label column
    features_df['label'] = logs_df['label']

    # Save features
    features_df.to_csv('logs/features.csv', index=False)

    # Save feature names for later use
    with open('model/feature_names.txt', 'w') as f:
        f.write('\n'.join(features_df.columns[:-1]))  # Exclude the label column

    print(f"Extracted {features_df.shape[1]-1} features from {len(features_df)} log entries.")
    print(f"Features saved to logs/features.csv")
    print(f"Feature names saved to model/feature_names.txt")
