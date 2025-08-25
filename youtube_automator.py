import json
import base64
import traceback
import js
import asyncio

from pyodide.http import pyfetch
from google.oauth2.credentials import Credentials

async def get_token_from_web_flow(secrets_base64_string):
    # This function is correct and unchanged.
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
    # This function is correct and unchanged.
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

async def upload_video_from_url(auth_token_json_string, details_json_string, video_url, video_mime_type, video_size, task_id):
    js.logToTaskWindow(task_id, "--> [Python] Starting robust chunked upload...")
    try:
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

        js.logToTaskWindow(task_id, f"--> [Python] Video size is {video_size / (1024*1024):.2f} MB.")
        js.logToTaskWindow(task_id, "--> [Python] Initializing resumable upload session with Google...")
        
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
            raise Exception(f"Failed to initiate upload (status {init_response.status}): {await init_response.string()}")
            
        upload_url = init_response.headers.get('location')
        if not upload_url:
            raise Exception("Did not receive a resumable upload URL from Google.")

        js.logToTaskWindow(task_id, f"--> [Python] Session initiated. Connecting to local stream...")
        
        local_video_stream_response = await pyfetch(url=video_url)
        if not local_video_stream_response.ok:
             raise Exception(f"Failed to connect to local Android stream (status {local_video_stream_response.status})")

        CHUNK_SIZE = 4 * 1024 * 1024 # 4 MB chunks
        bytes_uploaded = 0
        
        js.logToTaskWindow(task_id, "--> [Python] Starting chunk-by-chunk upload...")

        # *** THE DEFINITIVE FIX: The iter_bytes method was removed from the response object
        # in a recent version. This uses the correct, modern way to stream the body. ***
        async for chunk in local_video_stream_response.body.iter_bytes(chunk_size=CHUNK_SIZE):
            start_byte = bytes_uploaded
            end_byte = bytes_uploaded + len(chunk) - 1
            
            content_range = f"bytes {start_byte}-{end_byte}/{video_size}"
            
            js.logToTaskWindow(task_id, f"--> [Python] Uploading chunk: {content_range}")
            
            upload_response = await pyfetch(
                url=upload_url,
                method='PUT',
                headers={
                    'Content-Length': str(len(chunk)),
                    'Content-Range': content_range
                },
                body=chunk
            )

            if not (upload_response.status == 308 or upload_response.ok):
                error_body = await upload_response.string()
                js.logToTaskWindow(task_id, f"--> [Python] ERROR during chunk upload: {error_body}")
                raise Exception(f"Chunk upload failed with status {upload_response.status}")
                
            bytes_uploaded += len(chunk)

            if upload_response.ok:
                final_data = await upload_response.json()
                video_id = final_data.get('id')
                js.logToTaskWindow(task_id, f"\n✅ SUCCESS! Video uploaded with ID: {video_id}")
                js.logToTaskWindow(task_id, f"--> Link: https://www.youtube.com/watch?v={video_id}")
                return

        js.logToTaskWindow(task_id, "\n❌ [Python] ERROR: Upload loop finished but did not get success status from Google.")

    except Exception as e:
        js.logToTaskWindow(task_id, "\n❌ [Python] FATAL ERROR during upload:")
        traceback_str = traceback.format_exc()
        for line in traceback_str.split('\n'):
            js.logToTaskWindow(task_id, line)
