import json
import boto3
import os
from datetime import datetime

sns_client = boto3.client('sns')
guardduty_client = boto3.client('guardduty')
ec2_client = boto3.client('ec2')

SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
ENVIRONMENT = os.environ['ENVIRONMENT']

def lambda_handler(event, context):
    """
    Process GuardDuty findings and take automated response actions
    """
    print(f"Received event: {json.dumps(event)}")
    
    try:
        # Extract finding details
        detail = event['detail']
        finding_type = detail['type']
        severity = detail['severity']
        resource = detail.get('resource', {})
        
        # Prepare notification message
        message = format_finding_message(detail)
        
        # Send SNS notification
        send_sns_notification(message, finding_type, severity)
        
        # Take automated response based on finding type
        if 'UnauthorizedAccess' in finding_type:
            handle_unauthorized_access(detail)
        elif 'Recon' in finding_type:
            handle_reconnaissance(detail)
        elif 'CryptoCurrency' in finding_type:
            handle_crypto_mining(detail)
        
        return {
            'statusCode': 200,
            'body': json.dumps('Finding processed successfully')
        }
        
    except Exception as e:
        print(f"Error processing finding: {str(e)}")
        raise

def format_finding_message(detail):
    """Format GuardDuty finding into readable message"""
    return f"""
    GuardDuty Security Alert - {ENVIRONMENT}
    
    Finding Type: {detail['type']}
    Severity: {detail['severity']}
    Description: {detail['description']}
    
    Resource Details:
    {json.dumps(detail.get('resource', {}), indent=2)}
    
    Time: {detail['updatedAt']}
    Region: {detail['region']}
    Account: {detail['accountId']}
    
    Action Required: Please investigate this finding immediately.
    """

def send_sns_notification(message, finding_type, severity):
    """Send SNS notification"""
    subject = f"[{ENVIRONMENT}] GuardDuty Alert - {finding_type} (Severity: {severity})"
    
    response = sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=message
    )
    
    print(f"SNS notification sent: {response['MessageId']}")

def handle_unauthorized_access(detail):
    """Handle unauthorized access findings"""
    print("Processing unauthorized access finding...")
    
    resource = detail.get('resource', {})
    instance_details = resource.get('instanceDetails', {})
    instance_id = instance_details.get('instanceId')
    
    if instance_id:
        print(f"Isolating instance: {instance_id}")
        # Add logic to isolate instance (change security group, etc.)
        # This is a placeholder - implement based on your requirements

def handle_reconnaissance(detail):
    """Handle reconnaissance findings"""
    print("Processing reconnaissance finding...")
    # Implement reconnaissance response logic

def handle_crypto_mining(detail):
    """Handle cryptocurrency mining findings"""
    print("Processing crypto mining finding...")
    # Implement crypto mining response logic
