#!/usr/bin/env python3
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
import joblib
import re
import requests
import os
import argparse
from datetime import datetime

class LogAnalyzer:
    def __init__(self, model_path='model'):
        self.model = load_model(f'/home/pslearner/Desktop/ai-threat-detection/model/threat_detection_model')
        self.scaler = joblib.load(f'/home/pslearner/Desktop/ai-threat-detection/model/scaler.pkl')
        with open(f'/home/pslearner/Desktop/ai-threat-detection/model/feature_names.txt', 'r') as f:
            self.feature_names = [line.strip() for line in f.readlines()]

    def parse_log_line(self, log_line):
        log_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)(?:\[(\d+)\])?:\s+(.*)'
        match = re.match(log_pattern, log_line)
        if match:
            timestamp, host, program, pid, message = match.groups()
            return {'timestamp': timestamp, 'host': host, 'program': program,
                    'pid': pid if pid else '', 'message': message}
        return None

    def extract_features_single(self, log_entry):
        df = pd.DataFrame([log_entry])
        df['datetime'] = pd.to_datetime(df['timestamp'], format='%b %d %H:%M:%S', errors='coerce')
        df['hour'] = df['datetime'].dt.hour
        df['failed_password'] = df['message'].str.contains('Failed password', case=False).astype(int)
        df['accepted_login'] = df['message'].str.contains('Accepted', case=False).astype(int)
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        df['has_ip'] = df['message'].str.contains(ip_pattern).astype(int)
        ip_match = re.search(ip_pattern, log_entry['message'])
        ip_address = ip_match.group(0) if ip_match else None
        user_pattern = r'user (\w+)|for (\w+) from'
        user_match = re.search(user_pattern, log_entry['message'])
        username = user_match.group(1) or user_match.group(2) if user_match else None
        df['root_access'] = df['message'].str.contains('root', case=False).astype(int)
        df['user_mod'] = df['message'].str.contains('user|useradd|usermod|password changed', case=False).astype(int)
        df['sudo_cmd'] = df['message'].str.contains('sudo', case=False).astype(int)
        df['invalid_user'] = df['message'].str.contains('invalid user', case=False).astype(int)
        df['system_cmd'] = df['message'].str.contains('/bin/|/usr/bin/|wget|curl|bash', case=False).astype(int)
        df['suspicious_tool'] = df['message'].str.contains('nc |netcat|nmap', case=False).astype(int)
        df['log_manipulation'] = df['message'].str.contains('rm -rf|sed -i|/var/log', case=False).astype(int)
        df['backdoor'] = df['message'].str.contains('backdoor', case=False).astype(int)
        program_dummies = pd.DataFrame()
        for feature in self.feature_names:
            if feature.startswith('program_'):
                program_name = feature.replace('program_', '')
                program_dummies[feature] = [1 if df['program'].iloc[0] == program_name else 0]
        feature_df = pd.DataFrame(0, index=[0], columns=self.feature_names)
        for col in df.columns:
            if col in feature_df.columns:
                feature_df[col] = df[col].values
        for col in program_dummies.columns:
            if col in feature_df.columns:
                feature_df[col] = program_dummies[col].values
        return feature_df, ip_address, username

    def predict(self, log_line):
        log_entry = self.parse_log_line(log_line)
        if not log_entry: return None
        features, ip_address, username = self.extract_features_single(log_entry)
        scaled_features = self.scaler.transform(features)
        prediction = self.model.predict(scaled_features)[0][0]
        is_suspicious = bool(prediction > 0.5)
        return {'is_suspicious': is_suspicious, 'confidence': float(prediction),
                'ip_address': ip_address, 'username': username,
                'log_entry': log_entry, 'raw_log': log_line}

class TheHiveConnector:
    def __init__(self, api_url, api_key):
        self.api_url = api_url
        self.headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}

    def create_alert(self, title, description, severity, source, artifacts=None):
        alert_data = {
            "title": title, "description": description, "type": "external", "source": source,
            "sourceRef": f"{source}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "severity": severity, "tlp": 2, "pap": 2, "tags": ["ai-detection", "automated-alert"]
        }
        if artifacts: alert_data["artifacts"] = artifacts
        try:
            response = requests.post(f"{self.api_url}/api/alert", headers=self.headers, json=alert_data)
            if response.status_code == 201:
                print(f"Alert created successfully: {response.json()['_id']}")
                return response.json()['_id']
            else:
                print(f"Failed to create alert: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"Error creating alert: {str(e)}")
            return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Log file threat detection')
    parser.add_argument('--file', type=str, help='Path to the log file to analyze')
    parser.add_argument('--line', type=str, help='Single log line to analyze')
    parser.add_argument('--hive', action='store_true', help='Send alerts to TheHive')
    parser.add_argument('--hive_url', type=str, default='http://localhost:9000', help='TheHive URL')
    parser.add_argument('--hive_key', type=str, help='TheHive API key')
    args = parser.parse_args()

    analyzer = LogAnalyzer()
    hive_connector = None
    if args.hive:
        if not args.hive_key:
            print("Error: TheHive API key is required when using --hive")
            exit(1)
        hive_connector = TheHiveConnector(args.hive_url, args.hive_key)

    if args.line:
        result = analyzer.predict(args.line)
        if result:
            print(f"Suspicious: {'Yes' if result['is_suspicious'] else 'No'}")
            print(f"Confidence: {result['confidence']:.4f}")
            print(f"IP: {result['ip_address']}, Username: {result['username']}")
            if args.hive and result['is_suspicious']:
                artifacts = []
                if result['ip_address']:
                    artifacts.append({"dataType": "ip", "data": result['ip_address'],
                                    "message": "Source IP from suspicious log"})
                if result['username']:
                    artifacts.append({"dataType": "other", "data": result['username'],
                                    "message": "Username from suspicious log"})
                hive_connector.create_alert(
                    title=f"Suspicious Activity: {result['log_entry']['program']}",
                    description=f"## AI Detection Alert\n\nConfidence: {result['confidence']:.4f}\nSource: {result['log_entry']['host']}\nProgram: {result['log_entry']['program']}\nTime: {result['log_entry']['timestamp']}\n\nMessage:\n```\n{result['log_entry']['message']}\n```",
                    severity=2, source="AI-ThreatDetection", artifacts=artifacts)

    elif args.file:
        with open(args.file, 'r') as f:
            lines = f.readlines()
        suspicious_count = 0
        for line in lines:
            line = line.strip()
            result = analyzer.predict(line)
            if result and result['is_suspicious']:
                suspicious_count += 1
                print(f"SUSPICIOUS: {line}")
                print(f"Confidence: {result['confidence']:.4f}, IP: {result['ip_address']}")
                if args.hive:
                    artifacts = []
                    if result['ip_address']:
                        artifacts.append({"dataType": "ip", "data": result['ip_address'],
                                        "message": "Source IP from suspicious log"})
                    if result['username']:
                        artifacts.append({"dataType": "other", "data": result['username'],
                                        "message": "Username from suspicious log"})
                    hive_connector.create_alert(
                        title=f"Suspicious Activity: {result['log_entry']['program']}",
                        description=f"## AI Detection Alert\n\nConfidence: {result['confidence']:.4f}\nSource: {result['log_entry']['host']}\nProgram: {result['log_entry']['program']}\nTime: {result['log_entry']['timestamp']}\n\nMessage:\n```\n{result['log_entry']['message']}\n```",
                        severity=2, source="AI-ThreatDetection", artifacts=artifacts)
        print(f"\nAnalysis complete. Found {suspicious_count} suspicious log entries out of {len(lines)} total.")
    else:
        print("Please provide a log file with --file or a single log line with --line")
