"""Sends notification to users."""

import os
from time import strftime, gmtime
from uuid import uuid4

import requests


class UserNotification:
    """Generates report containing descriptive data for dependencies."""

    @staticmethod
    def send_notification(notification, token):
        """Send notification to the OSIO notification service."""
        url = os.getenv('NOTIFICATION_SERVICE_HOST', '').strip()

        endpoint = '{url}/api/notify'.format(url=url)
        auth = 'Bearer {token}'.format(token=token)
        resp = requests.post(endpoint, json=notification, headers={'Authorization': auth})
        if resp.status_code == 202:
            return {'status': 'success'}
        else:
            resp.raise_for_status()

    @staticmethod
    def generate_notification(report):
        """Generate notification structure from the build report."""
        result = {
            "data": {
                "attributes": {
                    "custom": report,
                    "id": report.get('repo_url', ""),
                    # I guess we need to change this type
                    "type": "analytics.notify.cve"
                },
                "id": str(uuid4()),
                "type": "notifications"
            }
        }
        result["data"]["attributes"]["custom"]["scanned_at"] = \
            strftime("%a, %d %B %Y %T GMT", gmtime())
        vulnerable_deps = result["data"]["attributes"]["custom"]["vulnerable_deps"]
        total_cve_count = 0

        for deps in vulnerable_deps:
            total_cve_count += int(deps['cve_count'])
        result["data"]["attributes"]["custom"]["cve_count"] = total_cve_count

        return result