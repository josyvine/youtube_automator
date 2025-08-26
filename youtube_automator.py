import json
import base64
import traceback
import js
import asyncio

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


# --- NEW STREAMING UPLOADER ---
class StreamingUploader:
    """
    Manages the state for a single, memory-efficient, streaming video upload.
    """
    def __init__(self, task_id, auth_token_json, details_json, mime_type, total_size):
        self.task_id = task_id
        self.auth_token = json.loads(auth_token_json)
        self.details = json.loads(details_json)
        self.mime_type = mime_type
        self.total_size = total_size
        self.upload_url = None
        self.bytes_uploaded = 0
        self.final_response_data = None # Will store the success response

    def get_progress_percent(self):
        if self.total_size == 0:
            return 0
        return (self.bytes_uploaded / self.total_size) * 100

    async def initiate_session(self):
        js.logToTaskWindow(self.task_id, "--> [Python] Initializing resumable upload session...")
        metadata_body = {
            'snippet': {
                'title': self.details['title'],
                'description': self.details['description'],
            },
            'status': {'privacyStatus': self.details['privacy']}
        }
        
        init_response = await pyfetch(
            url='https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status',
            method='POST',
            headers={
                'Authorization': f'Bearer {self.auth_token["token"]}',
                'Content-Type': 'application/json; charset=UTF-8',
                'X-Upload-Content-Type': self.mime_type,
                'X-Upload-Content-Length': str(self.total_size) 
            },
            body=json.dumps(metadata_body)
        )
        
        if not init_response.ok:
            raise Exception(f"Failed to initiate session (status {init_response.status}): {await init_response.string()}")
            
        self.upload_url = init_response.headers.get('location')
        if not self.upload_url:
            raise Exception("Did not receive an upload URL from Google.")
        
        js.logToTaskWindow(self.task_id, "--> [Python] Session initiated. Ready for chunks.")

    async def upload_chunk(self, chunk_base64):
        chunk_bytes = base64.b64decode(chunk_base64)
        
        upload_response = await pyfetch(
            url=self.upload_url,
            method='PUT',
            headers={'Content-Length': str(len(chunk_bytes))},
            body=chunk_bytes
        )

        # THE FIX: Check for the final success code (200 OK) here.
        if upload_response.status == 200:
            # This was the final chunk and the upload is complete.
            self.final_response_data = await upload_response.json()
        elif upload_response.status == 308:
            # This is the expected "in progress" response.
            pass
        else:
            # Any other response is an unexpected error.
            raise Exception(f"Chunk upload failed with status {upload_response.status}: {await upload_response.string()}")
        
        self.bytes_uploaded += len(chunk_bytes)

    def finalize_upload(self):
        # THE FIX: This function no longer makes a network call.
        # It relies on the data captured during the final 'upload_chunk' call.
        if self.final_response_data:
            video_id = self.final_response_data.get('id')
            privacy_status = self.details.get('privacy', 'private')

            js.logToTaskWindow(self.task_id, f"\n✅ SUCCESS! Video uploaded with ID: {video_id}")
            js.logToTaskWindow(self.task_id, "--> NOTE: The video is now processing on YouTube.")
            js.logToTaskWindow(self.task_id, f"--> It was uploaded as '{privacy_status}' and may take several minutes to appear in your YouTube Studio 'Content' section.")
        else:
            # This case means JS called finalize, but we never received a 200 OK response from Google.
            # The upload must have failed or was incomplete.
            js.logToTaskWindow(self.task_id, f"\n❌ [Python] ERROR: Finalization called, but upload did not complete successfully.")
            js.logToTaskWindow(self.task_id, f"--> Last known progress: {self.get_progress_percent():.1f}%. Check for earlier errors.")


# --- GLOBAL SESSION MANAGER FOR JAVASCRIPT ---
upload_sessions = {}

async def initiate_upload_session(task_id, auth_token_json, details_json, mime_type, total_size):
    try:
        uploader = StreamingUploader(task_id, auth_token_json, details_json, mime_type, total_size)
        upload_sessions[task_id] = uploader
        await uploader.initiate_session()
    except Exception as e:
        js.logToTaskWindow(task_id, f"❌ [Python] ERROR during initiation: {str(e)}")
        traceback.print_exc()
        raise e

async def upload_chunk(task_id, chunk_base64):
    try:
        if task_id not in upload_sessions:
            raise Exception(f"No active session for task_id: {task_id}")
        await upload_sessions[task_id].upload_chunk(chunk_base64)
    except Exception as e:
        js.logToTaskWindow(task_id, f"❌ [Python] ERROR during chunk upload: {str(e)}")
        traceback.print_exc()
        raise e

async def finalize_upload(task_id):
    try:
        if task_id not in upload_sessions:
            raise Exception(f"No active session for task_id: {task_id}")
        
        # The 'await' is removed as the new finalize_upload is not an async network call.
        upload_sessions[task_id].finalize_upload()

    except Exception as e:
        js.logToTaskWindow(task_id, f"❌ [Python] ERROR during finalization: {str(e)}")
        traceback.print_exc()
        raise e
    finally:
        # Clean up session to free memory, regardless of success or failure
        if task_id in upload_sessions:
            del upload_sessions[task_id]
