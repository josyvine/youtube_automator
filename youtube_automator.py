import io
import sys
import json
import base64
import asyncio
import traceback
import js
import httplib2 # <-- REQUIRED IMPORT FOR THE FIX

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from googleapiclient.http import MediaIoBaseUpload


async def get_token_from_web_flow(secrets_base64_string):
    try:
        secrets_json_string = base64.b64decode(secrets_base64_string).decode('utf-8')
        client_config = json.loads(secrets_json_string)
        
        redirect_uri = 'http://localhost'

        flow = InstalledAppFlow.from_client_config(
            client_config,
            scopes=['https://www.googleapis.com/auth/youtube.upload'],
            redirect_uri=redirect_uri
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


# ==============================================================================
# THIS IS THE CORRECTED UPLOAD FUNCTION
# ==============================================================================
def upload_video(auth_token_json_string, video_base64_string, details_json_string):
    try:
        auth_token = json.loads(auth_token_json_string)
        details = json.loads(details_json_string)
        
        print("--> Initializing YouTube API client...")
        credentials = Credentials(**auth_token)

        # ------------------- THIS IS THE FIX -------------------
        # 1. Create a custom httplib2.Http object with a long timeout.
        #    600 seconds = 10 minutes. This prevents the TimeoutError.
        http_with_timeout = httplib2.Http(timeout=600)

        # 2. Build the YouTube service object, passing in our custom http client.
        #    The credentials object authorizes our custom client.
        youtube = build(
            'youtube', 
            'v3', 
            credentials=credentials, 
            http=credentials.authorize(http_with_timeout)
        )
        # ----------------- END OF FIX -----------------
        
        print("--> YouTube client created successfully.")

        body = {
            'snippet': {
                'title': details.get('title', 'Default Title'),
                'description': details.get('description', 'Default Description'),
                'categoryId': '22'
            },
            'status': {
                'privacyStatus': details.get('privacy', 'private')
            }
        }
        print(f"--> Video Title: {details.get('title')}")
        print(f"--> Privacy Status: {details.get('privacy')}")

        print("--> Decoding video data...")
        video_bytes = base64.b64decode(video_base64_string)
        video_file = io.BytesIO(video_bytes)
        print("--> Video data ready for upload.")
        
        media = MediaIoBaseUpload(
            video_file, 
            mimetype='video/*', 
            chunksize=10*1024*1024, # Using a reasonable chunk size for better reliability 
            resumable=True
        )

        print("--> Starting video upload to YouTube. This may take a while...")
        request = youtube.videos().insert(
            part=",".join(body.keys()),
            body=body,
            media_body=media
        )
        
        response = None
        while response is None:
            status, response = request.next_chunk()
            if status:
                print(f"--> Uploaded {int(status.progress() * 100)}%")

        print("\n✅ SUCCESS: Video uploaded successfully!")
        print(f"--> Video ID: {response.get('id')}")

    except Exception as e:
        print(f"\n❌ ERROR during upload process: {e}")
        traceback.print_exc()
