# --- START OF CORRECTED youtube_automator.py (v3) ---

import io
import sys
import json
import base64
import asyncio
import traceback
import js
import httplib2 

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from googleapiclient.http import MediaIoBaseUpload
from google_auth_httplib2 import AuthorizedHttp

# --- [UNCHANGED] Authorization Flow ---
async def get_token_from_web_flow(secrets_base64_string):
    # This function is already async, so it's correct.
    try:
        secrets_json_string = base64.b64decode(secrets_base64_string).decode('utf-8')
        client_config = json.loads(secrets_json_string)
        
        flow = InstalledAppFlow.from_client_config(
            client_config,
            scopes=['https://www.googleapis.com/auth/youtube.upload'],
            redirect_uri='http://localhost'
        )

        auth_url, _ = flow.authorization_url(prompt='consent')
        js.open_auth_url_in_browser(auth_url)
        
        print("--> Waiting for authorization code from the app...")
        auth_code = await js.waitForAuthCode()

        if not auth_code or auth_code.strip() == "":
            raise Exception("Authorization code was not received or was empty.")

        print("--> Authorization code received. Fetching token...")
        
        flow.fetch_token(code=auth_code)
        creds = flow.credentials
        
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
        js.deliverAuthCodeToWeb(None) 
        return None

# --- [CORRECTED ASYNC] Upload Function with Diagnostics ---
# NOTICE THE 'async' KEYWORD ADDED HERE
async def upload_video(auth_token_json_string, video_base64_string, details_json_string):
    try:
        print("\n\n---> RUNNING SCRIPT WITH ASYNC FIX <---\n")
        print("--> [Step 1/7] Parsing credentials and video details...")
        auth_token = json.loads(auth_token_json_string)
        details = json.loads(details_json_string)
        credentials = Credentials(**auth_token)
        print("--> Credentials parsed successfully.")

        print("--> [Step 2/7] Initializing HTTP client with a 15-minute timeout...")
        http_with_timeout = httplib2.Http(timeout=900)
        authorized_http = AuthorizedHttp(credentials, http=http_with_timeout)
        
        print("--> [Step 3/7] Building YouTube API service client...")
        youtube = build('youtube', 'v3', http=authorized_http, cache_discovery=False)
        print("--> YouTube client created successfully.")

        body = {
            'snippet': {
                'title': details.get('title', 'Untitled Video'),
                'description': details.get('description', 'No Description'),
                'categoryId': '22'
            },
            'status': {'privacyStatus': details.get('privacy', 'private')}
        }
        print(f"--> Video Title: {body['snippet']['title']}")
        print(f"--> Privacy Status: {body['status']['privacyStatus']}")

        print("--> [Step 4/7] Decoding video data from Base64...")
        video_bytes = base64.b64decode(video_base64_string)
        video_file = io.BytesIO(video_bytes)
        file_size_mb = len(video_bytes) / (1024 * 1024)
        print(f"--> Video data ready. Size: {file_size_mb:.2f} MB")
        
        chunk_size = 2 * 1024 * 1024
        print(f"--> [Step 5/7] Creating resumable media upload object (Chunk size: 2MB)...")
        media = MediaIoBaseUpload(video_file, mimetype='video/*', chunksize=chunk_size, resumable=True)

        print("--> [Step 6/7] Building the final API request...")
        request = youtube.videos().insert(part=",".join(body.keys()), body=body, media_body=media)
        
        print("\n--> [Step 7/7] Starting the ASYNCHRONOUS upload loop...")
        response = None
        while response is None:
            # THIS IS THE CRITICAL FIX: We now 'await' the sleep call.
            await asyncio.sleep(0)
            
            status, response = request.next_chunk()
            if status:
                print(f"--> Upload progress: {int(status.progress() * 100)}%")

        print("\n✅ SUCCESS: Video uploaded successfully!")
        print(f"--> Video ID: {response.get('id')}")

    except TimeoutError as e:
        print("\n" + "="*50)
        print("🛑 FATAL ERROR: Network TimeoutError Caught")
        print("="*50)
        print("The async fix did not work. This strongly points to a native Webview configuration issue.")
        traceback.print_exc()

    except Exception as e:
        print("\n" + "="*50)
        print(f"🛑 FATAL ERROR: An Unexpected Error Occurred: {type(e).__name__}")
        print("="*50)
        traceback.print_exc()
