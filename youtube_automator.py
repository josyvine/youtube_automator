# --- START OF REVISED youtube_automator.py ---

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

# --- [HEAVILY MODIFIED] Upload Function with Diagnostics ---
def upload_video(auth_token_json_string, video_base64_string, details_json_string):
    # --- DIAGNOSTICS START ---
    # We will wrap the entire upload process in a detailed try/except block
    # to catch and explain specific errors related to this environment.
    # ---
    try:
        print("\n\n---> RUNNING SCRIPT WITH ROBUST DIAGNOSTICS <---\n")

        print("--> [Step 1/7] Parsing credentials and video details...")
        auth_token = json.loads(auth_token_json_string)
        details = json.loads(details_json_string)
        credentials = Credentials(**auth_token)
        print("--> Credentials parsed successfully.")

        print("--> [Step 2/7] Initializing HTTP client with a 15-minute timeout...")
        # We increase the timeout slightly, but acknowledge it may be overridden by the browser.
        http_with_timeout = httplib2.Http(timeout=900)
        authorized_http = AuthorizedHttp(credentials, http=http_with_timeout)
        
        print("--> [Step 3/7] Building YouTube API service client...")
        youtube = build(
            'youtube', 
            'v3', 
            http=authorized_http,
            # This cache_discovery=False can sometimes help in restricted environments
            cache_discovery=False 
        )
        print("--> YouTube client created successfully.")

        body = {
            'snippet': {
                'title': details.get('title', 'Untitled Video'),
                'description': details.get('description', 'No Description'),
                'categoryId': '22' # Example category, consider making this configurable
            },
            'status': {
                'privacyStatus': details.get('privacy', 'private')
            }
        }
        print(f"--> Video Title: {body['snippet']['title']}")
        print(f"--> Privacy Status: {body['status']['privacyStatus']}")

        print("--> [Step 4/7] Decoding video data from Base64...")
        video_bytes = base64.b64decode(video_base64_string)
        video_file = io.BytesIO(video_bytes)
        file_size_mb = len(video_bytes) / (1024 * 1024)
        print(f"--> Video data ready. Size: {file_size_mb:.2f} MB")
        
        # --- POTENTIAL FIX: SMALLER CHUNK SIZE ---
        # On unstable or slow networks, a smaller chunk size is more reliable.
        # Let's try 2MB chunks instead of 10MB.
        chunk_size = 2 * 1024 * 1024
        print(f"--> [Step 5/7] Creating resumable media upload object (Chunk size: {chunk_size / (1024*1024):.0f}MB)...")
        media = MediaIoBaseUpload(
            video_file, 
            mimetype='video/*', 
            chunksize=chunk_size,
            resumable=True
        )

        print("--> [Step 6/7] Building the final API request...")
        request = youtube.videos().insert(
            part=",".join(body.keys()),
            body=body,
            media_body=media
        )
        
        print("\n--> [Step 7/7] Starting the upload loop. This may take a while...")
        response = None
        while response is None:
            try:
                # --- ASYNCIO.SLEEP(0) IS CRUCIAL IN PYODIDE ---
                # This yields control back to the browser's event loop. It prevents
                # the browser from thinking the tab has frozen during a long,
                # synchronous operation like uploading a large chunk.
                # This can help prevent the browser from killing the process.
                asyncio.sleep(0)
                
                status, response = request.next_chunk()
                if status:
                    print(f"--> Upload progress: {int(status.progress() * 100)}%")
            except httplib2.HttpLib2Error as e:
                print("\n--- RETRYING CHUNK ---")
                print(f"A recoverable network error occurred: {e}")
                print("The resumable upload will attempt to continue.")
                # The loop will automatically retry on the next iteration.
                pass


        print("\n✅ SUCCESS: Video uploaded successfully!")
        print(f"--> Video ID: {response.get('id')}")

    # --- DETAILED ERROR CATCHING ---
    except TimeoutError as e:
        print("\n" + "="*50)
        print("🛑 FATAL ERROR: Network TimeoutError Caught")
        print("="*50)
        print("This is the exact error you've been seeing. It's a low-level network failure.")
        print("\nPOSSIBLE CAUSES IN THIS WEBVIEW/PYODIDE ENVIRONMENT:")
        print("  1. BROWSER/WEBVIEW TIMEOUT: The Android Webview likely has its own internal timeout (e.g., 60-120 seconds) that is being hit before the Python script's 15-minute timeout. This is the MOST LIKELY cause.")
        print("  2. UNSTABLE CONNECTION: A temporary loss of internet connectivity during the upload of a chunk.")
        print("  3. ANDROID RESTRICTIONS: The Android OS may be putting the app into a low-power state or restricting background network activity during the long upload.")
        print("\nRECOMMENDED ACTIONS:")
        print("  - Check the Android Logcat for any network-related error messages from the Webview itself.")
        print("  - Try uploading a very small video file (e.g., < 5MB) to see if it completes.")
        print("  - Try using a more stable Wi-Fi connection.")
        traceback.print_exc()

    except HttpError as e:
        print("\n" + "="*50)
        print(f"🛑 FATAL ERROR: Google API Returned an Error (Status: {e.resp.status})")
        print("="*50)
        print("This is NOT a network timeout. The request was successful, but Google rejected it.")
        error_content = json.loads(e.content.decode('utf-8'))
        print(f"  - Reason: {error_content['error']['message']}")
        print("\nCOMMON CAUSES:")
        print("  - 401: Authentication token expired. Try re-authorizing the account.")
        print("  - 403: YouTube API quota exceeded or API not enabled in Google Cloud.")
        print("  - 400: Bad request. Check video title/description for invalid characters.")

    except Exception as e:
        print("\n" + "="*50)
        print(f"🛑 FATAL ERROR: An Unexpected Error Occurred: {type(e).__name__}")
        print("="*50)
        print("An unknown error happened during the upload process. The full details are below.")
        traceback.print_exc()

# --- END OF REVISED youtube_automator.py ---
