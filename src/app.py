import json
import re
import os
import boto3
import requests
import xml.etree.ElementTree as ET

drupal_major_version = os.getenv('DRUPAL_MAJOR_VERSION')
drupal_topic_arn = os.getenv('DRUPAL_TOPIC_ARN')

def lambda_handler(event, context):

    print('[INFO] Getting Drupal security feed...')
    url = 'https://www.drupal.org/node/3060/release/feed'
    resp = requests.get(url, timeout=20)

    with open('/tmp/feed.xml', 'wb') as f:
        f.write(resp.content)

    tree = ET.parse('/tmp/feed.xml')
    root = tree.getroot()

    found_vulnerability = False
    item_is_current_drupalversion = False
    release = "0.0.0"
    release_security = release

    print('[INFO] Checking new versions on security updates...')
    for item in root.findall('./channel/item'):
        item_version_has_vulnerability = False
        for child in item:
            if child.tag == 'title':
                if child.text.startswith(f'drupal {drupal_major_version}'):
                    item_is_current_drupalversion = True
                    release = child.text

            if child.tag == 'description' and item_is_current_drupalversion:
                descr = child.text
                if len(re.findall('security vulnerabilit', descr)) > 0:
                    print(f"[ Ok ] {release} fixes security vulnerabilities!")
                    found_vulnerability = True
                    release_security = release

    if found_vulnerability:
        print('[INFO] We found a new Drupal security release.  Lets see if this version is known to us...')
        ssm = boto3.client('ssm')
        resp = ssm.get_parameter(Name='DrupalVersionSecurityFix')
        latest_security_release = resp['Parameter']['Value']
        if release_security != latest_security_release:
            print('[WARN] New Drupal security version, sending out alert...')
            # Send out an alert, we have a new Drupal version fixing a secvuln
            sns = boto3.client('sns')
            resp = sns.publish(
                TopicArn=os.environ['DrupalReleaseAlertingTopic'],
                Message=f"Your current Drupal version has some security vulnerabilities. Please upgrade to {release_security}"
            )

            # update the SSM parameter with the new release
            print('[INFO] Updating the SSM parameter with the latest security release')
            resp = ssm.put_parameter(
                Name='DrupalVersionSecurityFix',
                Value=release_security,
                Overwrite=True
            )

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": f"Security vulnerabilities found in current drupal version => {found_vulnerability}"
        }),
    }
