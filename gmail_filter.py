from __future__ import print_function

import os.path
import sys

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://mail.google.com/', 'https://www.googleapis.com/auth/gmail.modify']

INFO_1Q4SF0Q_SPAM_LABEL_ID = 'Label_1719013976872123471'

DIR_BASE = os.path.dirname(__file__)
DIR_NAME = (DIR_BASE if DIR_BASE else '.') + '/'

TESTING = False
VERBOSE = False

def main():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists(DIR_NAME + 'token.json'):
        creds = Credentials.from_authorized_user_file(DIR_NAME + 'token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                DIR_NAME + 'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open(DIR_NAME + 'token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        # results = service.users().labels().list(userId='me').execute()
        # labels = results.get('labels', [])
        # sys.exit(0)
	# Begin user-defined logic
        # label_emails_from_sender(service, 'info_1q4sF0Q', INFO_1Q4SF0Q_SPAM_LABEL_ID)
        label_all_messages(service, 'info_1q4sF0Q', INFO_1Q4SF0Q_SPAM_LABEL_ID)

	# End user-defined logic

    except HttpError as error:
        print(f'An error occurred: {error}')


def label_all_messages(service, sender_address, label_id):
    result = service.users().messages().list(userId='me').execute()
    # messages = []
    if 'messages' in result:
        for message_id in [message['id'] for message in result['messages']]:
            sender = get_sender(service, message_id)
            if sender_address in sender:
                label_email(service, message_id, label_id)
        # messages.extend([message['id'] for message in result['messages']])
    while 'nextPageToken' in result:
        page_token = result['nextPageToken']
        result = service.users().messages().list(userId='me', pageToken=page_token).execute()
        if 'messages' in result:
            for message_id in [message['id'] for message in result['messages']]:
                sender = get_sender(service, message_id)
                if sender and 'info_1q4sF0Q' in sender:
                    label_email(service, message_id, label_id)
        if TESTING:
            break
            # messages.extend([message['id'] for message in result['messages']])

def get_message(service, user_id, msg_id):
  try:
    return service.users().messages().get(userId=user_id, id=msg_id, format='metadata').execute()
  except Exception as error:
    print('An error occurred: %s' % error)
    print('Relevant ID: %s' % msg_id)

def get_messages(service):
    messages = service.users().messages().list(userId='me').execute()['messages']
    message_ids = [message['id'] for message in messages]
    return message_ids

# Unused
def get_all_messages(service):
    result = service.users().messages().list(userId='me').execute()
    messages = []
    if 'messages' in result:
        messages.extend([message['id'] for message in result['messages']])
    while 'nextPageToken' in result:
        page_token = result['nextPageToken']
        result = service.users().messages().list(userId='me', pageToken=page_token).execute()
        if 'messages' in result:
            messages.extend([message['id'] for message in result['messages']])
        if TESTING:
            break
    print('Found {} messages'.format(len(messages)))
    if TESTING:
        return messages[:500]
    return messages

def get_sender(service, message_id):
    message = get_message(service, 'me', message_id)
    if not message:
        return ''
    for item in message['payload']['headers']:
        if item['name'] == 'From':
            return item['value']
    return ''

# Unused
def get_messages_from_sender(service, sender_name):
    # messages = get_messages(service)
    messages = get_all_messages(service)
    messages_from_sender = []
    for message_id in messages:
        try:
            sender = get_sender(service, message_id)
        except:
            continue
        if sender and sender_name in sender:
            messages_from_sender.append(message_id)
    return messages_from_sender

# Unused
def get_labels(service, message_id):
    message = get_message(service, 'me', message_id)
    return message['labelIds']

def label_exists_for_message(service, email_id, label_id):
    message = get_message(service, 'me', email_id)
    # existing_labels = message['labelIds']
    # return label_id in existing_labels
    return label_id in message['labelIds']

def label_email(service, email_id, label_id):
    print('Checking email with ID:  {}'.format(email_id))
    if label_exists_for_message(service, email_id, label_id):
        print('Label found.  Skipping.')
        return
    print('Labeling email with ID: {}'.format(email_id))
    result = service.users().messages().modify(
        userId='me',
        id=email_id,
        body={
            "addLabelIds": [label_id],
        },
    ).execute()
    if VERBOSE:
        print(result)

# Unused
def label_emails_from_sender(service, sender_name, label_id):
    print('Applying label ID {} to emails from {}'.format(label_id, sender_name))
    message_ids = get_messages_from_sender(service, sender_name)
    for message_id in message_ids:
        label_email(service, message_id, INFO_1Q4SF0Q_SPAM_LABEL_ID)


if __name__ == '__main__':
    main()
