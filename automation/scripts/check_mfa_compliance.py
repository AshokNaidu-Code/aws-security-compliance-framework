#!/usr/bin/env python3
"""
Script to check MFA compliance for IAM users
"""

import boto3
from datetime import datetime
import csv

iam_client = boto3.client('iam')

def check_mfa_compliance():
    """Check MFA status for all IAM users"""
    
    print("Checking MFA compliance for IAM users...")
    
    users = iam_client.list_users()['Users']
    compliance_report = []
    
    for user in users:
        username = user['UserName']
        mfa_devices = iam_client.list_mfa_devices(UserName=username)['MFADevices']
        
        compliance_status = {
            'Username': username,
            'MFA_Enabled': len(mfa_devices) > 0,
            'MFA_Devices': len(mfa_devices),
            'Created_Date': user['CreateDate'].strftime('%Y-%m-%d'),
            'Compliant': len(mfa_devices) > 0
        }
        
        compliance_report.append(compliance_status)
        
        if not compliance_status['Compliant']:
            print(f"⚠️  NON-COMPLIANT: User '{username}' does not have MFA enabled")
        else:
            print(f"✅ COMPLIANT: User '{username}' has MFA enabled")
    
    # Generate CSV report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_filename = f'mfa_compliance_report_{timestamp}.csv'
    
    with open(report_filename, 'w', newline='') as csvfile:
        fieldnames = ['Username', 'MFA_Enabled', 'MFA_Devices', 'Created_Date', 'Compliant']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        writer.writerows(compliance_report)
    
    print(f"\n📊 Compliance report saved to: {report_filename}")
    
    # Summary
    total_users = len(compliance_report)
    compliant_users = sum(1 for user in compliance_report if user['Compliant'])
    compliance_percentage = (compliant_users / total_users * 100) if total_users > 0 else 0
    
    print(f"\n📈 Summary:")
    print(f"Total Users: {total_users}")
    print(f"Compliant Users: {compliant_users}")
    print(f"Non-Compliant Users: {total_users - compliant_users}")
    print(f"Compliance Rate: {compliance_percentage:.2f}%")

if __name__ == "__main__":
    check_mfa_compliance()
