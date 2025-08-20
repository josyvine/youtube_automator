import io
import sys
import json
import base64
import asyncio
import js # Pyodide's bridge to JavaScript

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow # This was changed from InstalledAppFlow to match the Android redirect
from google.oauth2.credentials import Credentials
from googleapiclient.http import MediaIoBaseUpload

# ==============================================================================
# CORRECTED FUNCTION: get_token_from_web_flow
# This function has been updated to use the custom redirect URI from your Android app.
# ==============================================================================
async def get_token_from_web_flow(secrets_base64_string):
    """
    Handles the Google OAuth flow using a custom URI redirect for a WebView app.
    """
    try:
        # Step 1: Decode the secrets file data from base64
        secrets_json_string = base64.b64decode(secrets_base64_string).decode('utf-8')
        client_config = json.loads(secrets_json_string)
        
        # Step 2: Create a flow with the custom redirect URI that matches the Android app
        # This redirect_uri MUST EXACTLY MATCH the one in your Google Cloud Console
        # and correspond to the scheme/host in AndroidManifest.xml
        redirect_uri = 'com.yourname.youtubesuite.oauth2:/callback'

        flow = Flow.from_client_config(
            client_config,
            scopes=['https://www.googleapis.com/auth/youtube.upload'],
            redirect_uri=redirect_uri
        )

        # Step 3: Generate the authorization URL and tell JavaScript to open it
        auth_url, _ = flow.authorization_url(prompt='consent')
        js.open_auth_url_in_browser(auth_url)
        
        # Step 4: Wait for the JavaScript/Android bridge to deliver the auth code
        # This await pauses Python execution until deliverAuthCodeToWeb() is called in JS
        print("--> Waiting for authorization code from the app...")
        auth_code = await js.waitForAuthCode()

        if not auth_code or auth_code.strip() == "":
            raise Exception("Authorization code was not received.")

        print("--> Authorization code received. Fetching token...")
        
        # Step 5: Exchange the code for a token
        flow.fetch_token(code=auth_code)
        creds = flow.credentials
        
        # Step 6: Return the token data as a JSON string back to JavaScript
        return json.dumps({
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes
        })
    except Exception as e:
        print(f"\n❌ ERROR in auth flow: {e}")
        # Make sure the JS promise doesn't hang forever on failure
        js.deliverAuthCodeToWeb(None) 
        return None

# ==============================================================================
# ORIGINAL UNCHANGED FUNCTION: upload_video
# This is your complete function, restored and untouched.
# ==============================================================================
def upload_video(auth_token_json_string, video_base64_string, details_json_string):
    """
    Handles the entire video upload process using a saved token.
    """
    try:
        # Step 1: Load the data received from JavaScript
        auth_token = json.loads(auth_token_json_string)
        details = json.loads(details_json_string)
        
        print("--> Initializing YouTube API client...")
        credentials = Credentials(**auth_token)
        youtube = build('youtube', 'v3', credentials=credentials)
        print("--> YouTube client created successfully.")

        # Step 2: Prepare the video details for the API request
        body = {
            'snippet': {
                'title': details.get('title', 'Default Title'),
                'description': details.get('description', 'Default Description'),
                'categoryId': '22' # 22 = People & Blogs
            },
            'status': {
                'privacyStatus': details.get('privacy', 'private')
            }
        }
        print(f"--> Video Title: {details.get('title')}")
        print(f"--> Privacy Status: {details.get('privacy')}")

        # Step 3: Decode the video file data from Base64 into raw bytes
        print("--> Decoding video data...")
        video_bytes = base64.b64decode(video_base64_string)
        video_file = io.BytesIO(video_bytes)
        print("--> Video data ready for upload.")
        
        # Step 4: Create the object that handles the resumable upload
        media = MediaIoBaseUpload(video_file, mimetype='video/*', chunksize=-1, resumable=True)

        print("--> Starting video upload to YouTube. This may take a while...")
        request = youtube.videos().insert(
            part=",".join(body.keys()),
            body=body,
            media_body=media
        )
        
        # Step 5: Execute the upload and print progress
        response = None
        while response is None:
            status, response = request.next_chunk()
            if status:
                print(f"--> Uploaded {int(status.progress() * 100)}%")

        print("\n✅ SUCCESS: Video uploaded successfully!")
        print(f"--> Video ID: {response.get('id')}")

    except Exception as e:
        print(f"\n❌ ERROR during upload process: {e}")
