# --- START OF CORRECTED youtube_automator.py ---

import json
import base64
import traceback
import js
import asyncio  # Import asyncio for handling asynchronous operations
from google_auth_oauthlib.flow import InstalledAppFlow

# The function must be declared as 'async' to use 'await'
async def get_token_from_web_flow(secrets_base64_string):
    """
    Handles the Google OAuth2 flow to get user credentials.
    This part runs in the Pyodide terminal.
    """
    try:
        secrets_json_string = base64.b64decode(secrets_base64_string).decode('utf-8')
        client_config = json.loads(secrets_json_string)
        
        flow = InstalledAppFlow.from_client_config(
            client_config,
            scopes=['https://www.googleapis.com/auth/youtube.upload'],
            redirect_uri='http://localhost' # A placeholder for the web flow
        )

        auth_url, _ = flow.authorization_url(prompt='consent')
        js.open_auth_url_in_browser(auth_url)
        
        print("--> Waiting for authorization code from the app...")
        
        # FIX #1: You must 'await' the result from the JavaScript Promise/PyodideFuture.
        # This pauses the code until the user enters the code in the terminal.
        auth_code = await js.waitForAuthCode()

        if not auth_code or auth_code.strip() == "":
            raise Exception("Authorization code was not received or was empty.")

        print("--> Authorization code received. Fetching token...")
        
        # FIX #2: In Pyodide, blocking network calls must also be awaited.
        # We run it in a separate thread via asyncio.to_thread to prevent the UI from freezing.
        await asyncio.to_thread(flow.fetch_token, code=auth_code)
        
        creds = flow.credentials
        
        # Return the complete credentials as a JSON string
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

def prepare_upload_data(auth_token_json_string, details_json_string):
    """
    Takes the token and video details and combines them into a single JSON "work order"
    to be passed to the native Android uploader. This does NOT upload the video.
    """
    print("--> [Pyodide] Preparing token and metadata for native handoff...")
    try:
        # Load the JSON strings into Python dictionaries
        auth_token = json.loads(auth_token_json_string)
        details = json.loads(details_json_string)

        # Combine everything into one package for the Java code
        upload_package = {
            "credentials": auth_token,
            "metadata": details
        }
        
        print("--> [Pyodide] Data package is ready for handoff.")
        # Return the combined data as a single JSON string
        return json.dumps(upload_package)

    except Exception as e:
        print(f"\n❌ An error occurred while preparing data in Python:")
        traceback.print_exc()
        return None

# --- END OF CORRECTED youtube_automator.py ---
