import json
import base64
import traceback
import js
import asyncio
import io

from pyodide.http import pyfetch
from google.oauth2.credentials import Credentials

async def get_token_from_web_flow(secrets_base64_string):
    """
    Handles the Google OAuth2 flow to get user credentials. (Unchanged)
    """
    try:
        secrets_json_string = base64.b64decode(secrets_base64_string).decode('utf-8')
        client_config = json.loads(secrets_json_string)
        
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
    Tests the connection using pyfetch. (Unchanged)
    """
    print("--> [Python] Running connection test...")
    try:
        creds_data = json.loads(auth_token_json_string)
        access_token = creds_data['token']
        
        print("--> [Python] Attempting to fetch channel info using pyfetch...")
        response = await pyfetch(
            url='https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true',
            method='GET',
            headers={ 'Authorization': f'Bearer {access_token}' }
        )
        
        if not response.ok:
             raise Exception(f"API request failed with status {response.status}: {await response.string()}")

        data = await response.json()
        channel_title = data['items'][0]['snippet']['title']
        
        print(f"\n✅ SUCCESS: Connection to Google API is working!")
        print(f"--> Successfully fetched info for channel: {channel_title}")

    except Exception as e:
        print("\n❌ FAILED: An unexpected error occurred during Python connection test.")
        traceback.print_exc()

# --- CLASS TO HANDLE THE LOGIC FOR A SINGLE UPLOAD ---
class ChunkedVideoUploader:
    def __init__(self):
        self.video_stream = None
        self.task_id = None

    def start_new_upload(self, task_id):
        """Prepares the in-memory stream for a new file upload."""
        self.task_id = task_id
        self.video_stream = io.BytesIO()
        js.logToTaskWindow(self.task_id, "--> [Python] Uploader initialized and ready for chunks.")

    def append_chunk(self, chunk_base64):
        """Adds a new chunk of data to the in-memory stream."""
        try:
            decoded_chunk = base64.b64decode(chunk_base64)
            self.video_stream.write(decoded_chunk)
            return True
        except Exception as e:
            js.logToTaskWindow(self.task_id, f"❌ [Python] Error processing chunk: {e}")
            return False

    async def finalize_and_upload(self, auth_token_json_string, details_json_string, video_mime_type):
        """Performs the actual upload to Google after all chunks are received."""
        js.logToTaskWindow(self.task_id, "--> [Python] All chunks received. Finalizing upload...")
        details = {}
        try:
            self.video_stream.seek(0)
            video_bytes = self.video_stream.getvalue()
            video_size = len(video_bytes)
            
            self.video_stream.close()
            self.video_stream = None

            js.logToTaskWindow(self.task_id, f"--> [Python] Total video size: {video_size / (1024*1024):.2f} MB.")
            
            creds_data = json.loads(auth_token_json_string)
            access_token = creds_data['token']
            
            details = json.loads(details_json_string)
            metadata_body = {
                'snippet': {
                    'title': details['title'],
                    'description': details['description'],
                },
                'status': {
                    'privacyStatus': details['privacy']
                }
            }

            js.logToTaskWindow(self.task_id, "--> [Python] Initializing resumable upload session...")
            init_response = await pyfetch(
                url='https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status',
                method='POST',
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json; charset=UTF-8',
                    'X-Upload-Content-Type': video_mime_type,
                    'X-Upload-Content-Length': str(video_size) 
                },
                body=json.dumps(metadata_body)
            )
            
            if not init_response.ok:
                response_text = await init_response.string()
                raise Exception(f"Failed to initiate upload session (status {init_response.status}): {response_text}")
                
            upload_url = init_response.headers.get('location')
            if not upload_url:
                raise Exception("Did not receive an upload URL from Google.")

            js.logToTaskWindow(self.task_id, f"--> [Python] Session initiated. Uploading video data...")
            upload_response = await pyfetch(
                url=upload_url,
                method='PUT',
                body=video_bytes
            )

            if not upload_response.ok:
                 raise Exception(f"Video upload failed with status {upload_response.status}: {await upload_response.string()}")

            final_data = await upload_response.json()
            video_id = final_data.get('id')
            privacy_status = details.get('privacy', 'private')
            js.logToTaskWindow(self.task_id, f"\n✅ SUCCESS! Video uploaded with ID: {video_id}")
            js.logToTaskWindow(self.task_id, "--> NOTE: The video is now processing on YouTube.")
            js.logToTaskWindow(self.task_id, f"--> It was uploaded as '{privacy_status}' and may take several minutes to appear in your YouTube Studio 'Content' section.")


        except Exception as e:
            js.logToTaskWindow(self.task_id, "\n❌ [Python] FATAL ERROR during upload:")
            traceback_str = traceback.format_exc()
            for line in traceback_str.split('\n'):
                js.logToTaskWindow(self.task_id, line)

# --- GLOBAL SESSION MANAGER FOR JAVASCRIPT TO INTERACT WITH ---

# This dictionary holds an uploader instance for each concurrent task.
upload_sessions = {}

def start_new_upload(task_id):
    """Called by JS to create and prepare an uploader instance for a task."""
    if task_id in upload_sessions:
        js.logToTaskWindow(task_id, f"⚠️ [Python] Warning: Overwriting existing session for {task_id}.")
    
    uploader = ChunkedVideoUploader()
    upload_sessions[task_id] = uploader
    uploader.start_new_upload(task_id)
    return True

def append_chunk(task_id, chunk_base64):
    """Called by JS to append a chunk to a specific task's uploader."""
    if task_id not in upload_sessions:
        js.logToTaskWindow(task_id, f"❌ [Python] Error: No session found for {task_id} to append chunk.")
        return False
    return upload_sessions[task_id].append_chunk(chunk_base64)

async def finalize_and_upload(task_id, auth_token_json_string, details_json_string, video_mime_type):
    """Called by JS to finalize a specific task's upload and clean up."""
    if task_id not in upload_sessions:
        js.logToTaskWindow(task_id, f"❌ [Python] Error: No session found for {task_id} to finalize.")
        return

    uploader = upload_sessions[task_id]
    try:
        await uploader.finalize_and_upload(auth_token_json_string, details_json_string, video_mime_type)
    finally:
        # Clean up the session to free memory, regardless of success or failure.
        if task_id in upload_sessions:
            del upload_sessions[task_id]
