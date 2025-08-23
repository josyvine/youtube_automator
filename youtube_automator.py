# --- START OF FINAL, COMPLETE youtube_automator.py ---

import json
import base64
import traceback
import js
import asyncio
import io

# Pyodide doesn't have these by default, so we import them this way
from pyodide.http import pyfetch
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

async def get_token_from_web_flow(secrets_base64_string):
    """
    Handles the Google OAuth2 flow to get user credentials.
    """
    try:
        secrets_json_string = base64.b64decode(secrets_base64_string).decode('utf-8')
        client_config = json.loads(secrets_json_string)
        
        # We must use a custom flow for Pyodide as InstalledAppFlow is not fully compatible
        # This part remains mostly the same, but it's important to understand the context
        scopes = [
            'https://www.googleapis.com/auth/youtube.upload',
            'https://www.googleapis.com/auth/youtube.readonly'
        ]
        
        auth_uri = client_config['installed']['auth_uri']
        client_id = client_config['installed']['client_id']
        token_uri = client_config['installed']['token_uri']
        client_secret = client_config['installed']['client_secret']
        
        auth_url = (f"{auth_uri}?client_id={client_id}&redirect_uri=http://localhost"
                    f"&response_type=code&scope={' '.join(scopes)}&access_type=offline")

        js.open_auth_url_in_browser(auth_url)
        print("--> Waiting for authorization code from the app...")
        auth_code = await js.waitForAuthCode()

        if not auth_code or auth_code.strip() == "":
            raise Exception("Authorization code was not received or was empty.")

        print("--> Authorization code received. Fetching token...")
        
        response = await pyfetch(
            url=token_uri,
            method='POST',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            body=(f"code={auth_code}&client_id={client_id}&client_secret={client_secret}"
                  f"&redirect_uri=http://localhost&grant_type=authorization_code")
        )
        token_data = await response.json()
        
        creds = Credentials(
            token=token_data['access_token'],
            refresh_token=token_data.get('refresh_token'),
            token_uri=token_uri,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes
        )
        
        return json.dumps({
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes
        })
        
    except Exception as e:
        print(f"\n❌ A detailed error occurred in the Python authentication flow:")
        traceback.print_exc()
        return None

async def test_api_connection(auth_token_json_string):
    """
    Tests the connection to the YouTube API directly from Python.
    """
    print("--> [Python] Running connection test...")
    try:
        creds_data = json.loads(auth_token_json_string)
        credentials = Credentials(**creds_data)
        
        # The 'build' function is blocking, so we run it in a thread
        youtube = await asyncio.to_thread(build, 'youtube', 'v3', credentials=credentials)
        
        print("--> [Python] Attempting to fetch channel info...")
        # The 'execute' function is also blocking
        request = youtube.channels().list(part='snippet', mine=True)
        response = await asyncio.to_thread(request.execute)

        channel_title = response['items'][0]['snippet']['title']
        print(f"\n✅ SUCCESS: Connection to Google API is working!")
        print(f"--> Successfully fetched info for channel: {channel_title}")

    except Exception as e:
        print("\n❌ FAILED: An unexpected error occurred during Python connection test.")
        traceback.print_exc()

async def upload_video(auth_token_json_string, details_json_string, video_base64_string):
    """
    Handles the entire video upload process within Pyodide.
    """
    print("--> [Python] Starting full upload process...")
    try:
        # 1. Prepare credentials and YouTube service object
        creds_data = json.loads(auth_token_json_string)
        credentials = Credentials(**creds_data)
        youtube = await asyncio.to_thread(build, 'youtube', 'v3', credentials=credentials)

        # 2. Prepare video data
        print("--> [Python] Decoding Base64 video data...")
        video_bytes = base64.b64decode(video_base64_string)
        video_file = io.BytesIO(video_bytes)
        
        # 3. Prepare metadata
        details = json.loads(details_json_string)
        body = {
            'snippet': {
                'title': details['title'],
                'description': details['description'],
                'tags': details.get('tags', []),
                'categoryId': details.get('categoryId', '22')
            },
            'status': {
                'privacyStatus': details['privacy']
            }
        }

        # 4. Create the resumable upload object
        media = MediaIoBaseUpload(video_file, mimetype='application/octet-stream', chunksize=1024*1024, resumable=True)
        
        print("--> [Python] Initializing upload request...")
        request = youtube.videos().insert(
            part=",".join(body.keys()),
            body=body,
            media_body=media
        )

        # 5. Execute the upload in chunks and report progress
        response = None
        while response is None:
            # Run the blocking network call in a thread
            status, response = await asyncio.to_thread(request.next_chunk)
            if status:
                progress = int(status.progress() * 100)
                print(f"--> [Python] Upload Progress: {progress}%")

        print("\n✅ SUCCESS! Video uploaded with ID:", response.get('id'))

    except Exception as e:
        print("\n❌ [Python] FATAL ERROR during native upload:")
        traceback.print_exc()

# --- END OF FINAL, COMPLETE youtube_automator.py ---
