from __future__ import annotations

import base64, logging, re, requests
from dataclasses import dataclass
from typing import Optional
from pathlib import Path

from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request


# ========= LOGGING =========
logger = logging.getLogger(__name__)


# ========= PATTERNS =========
HOUSEHOLD_LINK_RE = re.compile(
    r"https://www\.netflix\.com/account/update-primary-location[^\s\]]+", re.IGNORECASE
)


# ========= CONFIG =========
@dataclass
class GmailConfig:
    scopes: list[str] = None
    credentials_file: str = "../data/credentials.json"
    token_file: str = "../data/token.json"

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = ["https://www.googleapis.com/auth/gmail.modify"]


# ========= UTILITIES =========
def b64url_decode(data: str) -> str:
    """Decode base64url encoded string."""
    return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")


# ========= GMAIL CLIENT =========
class GmailClient:
    def __init__(self, config: GmailConfig):
        self.config = config
        self.service = self._authenticate()


    def _authenticate(self):
        """Authenticate with Gmail API using OAuth2."""
        # Validate credentials file exists
        if not Path(self.config.credentials_file).exists():
            raise FileNotFoundError(
                f"Credentials file not found: {self.config.credentials_file}\n"
                "Please ensure credentials.json is exits and located in the data/ folder."
            )

        creds = None

        # Load existing token if available
        if Path(self.config.token_file).exists():
            logger.debug(f"Loading existing token from {self.config.token_file}")
            creds = Credentials.from_authorized_user_file(
                self.config.token_file, self.config.scopes
            )

        # Refresh or create new credentials
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                logger.debug("Refreshing expired credentials")
                creds.refresh(Request())
            else:
                logger.debug("Creating new credentials from client secrets")
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.config.credentials_file, self.config.scopes
                )
                creds = flow.run_local_server(port=0)

            # Save token for future use
            logger.debug(f"Saving token to {self.config.token_file}")
            with open(self.config.token_file, "w", encoding="utf-8") as f:
                f.write(creds.to_json())

        logger.info("Gmail authentication successful")
        return build("gmail", "v1", credentials=creds)


    def _extract_body_parts(self, payload: dict, mime_types: list[str]) -> dict[str, str]:
        """
        Extract specific MIME type bodies from email payload.

        Args:
            payload: Email payload structure
            mime_types: List of MIME types to extract (e.g., ["text/plain", "text/html"])

        Returns:
            Dictionary mapping MIME type to decoded body
        """
        bodies = {mime: None for mime in mime_types}
        stack = [payload]

        while stack:
            part = stack.pop()
            mime = part.get("mimeType")

            # Extract body if MIME type matches and not yet found
            if mime in mime_types and bodies[mime] is None:
                data = (part.get("body", {}) or {}).get("data")
                if data:
                    bodies[mime] = b64url_decode(data)
                    logger.debug(f"Extracted {mime} body")

            # Add child parts to stack
            for child in part.get("parts", []) or []:
                stack.append(child)

        return bodies


    def get_email_headers(self, msg_id: str) -> dict[str, str]:
        """Get email metadata (From, Subject, Date)."""
        logger.debug(f"Fetching headers for email {msg_id}")
        msg = (
            self.service.users()
            .messages()
            .get(
                userId="me",
                id=msg_id,
                format="metadata",
                metadataHeaders=["From", "Subject", "Date"],
            )
            .execute()
        )

        headers = msg.get("payload", {}).get("headers", [])
        return {h["name"]: h["value"] for h in headers}


    def get_email_body(self, msg_id: str, mime_types: Optional[list[str]] = None) -> dict[str, str]:
        """
        Get message body in specified MIME types.

        Args:
            msg_id: Gmail message ID
            mime_types: List of MIME types (default: both text/plain and text/html)

        Returns:
            Dictionary with MIME type keys and body values
        """
        if mime_types is None:
            mime_types = ["text/plain", "text/html"]

        logger.debug(f"Fetching message {msg_id} with MIME types: {mime_types}")
        msg = (
            self.service.users()
            .messages()
            .get(userId="me", id=msg_id, format="full")
            .execute()
        )

        payload = msg.get("payload", {}) or {}
        bodies = self._extract_body_parts(payload, mime_types)

        return {k: v or "" for k, v in bodies.items()}


    def check_email_criteria(self, msg_id: str, subject_text: str, body_text: str) -> bool:
        """
        Check if an email matches criteria on 2 levels:
        1. Subject contains subject_text
        2. Body contains body_text

        Args:
            msg_id: Gmail message ID to check
            subject_text: Text to search for in the subject line
            body_text: Text to search for in the message body

        Returns:
            True if both subject and body match, False otherwise
        """
        logger.debug(f"Checking email [{msg_id}]")

        # Get headers
        headers = self.get_email_headers(msg_id)
        subject = headers.get("Subject") or ""

        # Level 1: Check subject first (fast - already loaded)
        logger.debug(f"Checking subject for: '{subject_text}'")
        if subject_text not in subject:
            logger.debug(
                f"Subject mismatch. Expected: '{subject_text}', Got: '{subject}'"
            )
            return False

        logger.info(f"Email [{msg_id}] matches subject '{subject}'")

        # Level 2: Check body (slower - needs to fetch full email)
        logger.debug(f"Checking body for: '{body_text}'")
        bodies = self.get_email_body(msg_id)
        html_body = bodies.get("text/html", "")

        found = body_text in html_body
        if found:
            logger.info(f"Email [{msg_id}] contains: '{body_text}'")
        else:
            logger.info(f"Email [{msg_id}] doesn't contain: '{body_text}'")

        return found


    def get_unread_emails(self, max_results: int = 5) -> list[dict]:
        """
        Get unread messages.

        Returns:
            List of unread message dicts with From, Subject, Date, ID
        """
        logger.debug(f"Fetching unread emails (max {max_results})")
        res = (
            self.service.users()
            .messages()
            .list(userId="me", q="is:unread", maxResults=max_results)
            .execute()
        )

        messages = res.get("messages", [])
        if not messages:
            logger.info("No unread email")
            return []

        logger.info(f"Found {len(messages)} unread email(s)")
        results = []
        for m in messages:
            headers = self.get_email_headers(m["id"])
            message_info = {
                "id": m["id"],
                "from": headers.get("From"),
                "subject": headers.get("Subject"),
                "date": headers.get("Date"),
            }
            results.append(message_info)

        return results


    def mark_as_read(self, msg_id: str) -> None:
        """Mark a message as read."""
        logger.debug(f"Marking message {msg_id} as read")
        self.service.users().messages().modify(
            userId="me", id=msg_id, body={"removeLabelIds": ["UNREAD"]}
        ).execute()


    def extract_household_verification_link(self, msg_id: str) -> str | None:
        """
        Extract Netflix household verification link from message body.

        Args:
            msg_id: Gmail message ID

        Returns:
            Netflix household verification link if found, None otherwise
        """
        logger.debug(f"Extracting household verification link from message {msg_id}")
        bodies = self.get_email_body(msg_id)

        # Search in both plain text and HTML
        for body_text in [bodies.get("text/plain", ""), bodies.get("text/html", "")]:
            if match := HOUSEHOLD_LINK_RE.search(body_text):
                link = match.group(0)
                logger.info(f"Found household verification link: {link}")
                return link

        logger.debug("No household verification link found in message")
        return None


# ========= MAIN =========
def main(debug: bool = False, info: bool = False):
    # Configure logging based on flags
    if debug:
        log_level = logging.DEBUG
    elif info:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING  # Only show warnings and errors

    logging.basicConfig(level=log_level, format="[%(levelname)-5s] - %(message)s")

    config = GmailConfig()
    client = GmailClient(config)

    # Get unread emails
    messages = client.get_unread_emails(max_results=5)
    for msg in messages:
        if info or debug:
            logger.debug(
                f"Subject: {msg['subject']} | Date: {msg['date']}"
            )

        # Check this email
        result = client.check_email_criteria(
            msg_id=msg["id"],
            subject_text="Important: How to update your Netflix household",
            body_text="Requested by Mom",
        )

        if result:
            # Extract the household link
            link = client.extract_household_verification_link(msg["id"])
            if link:
                try:
                    response = requests.get(link, timeout=20)
                    response.raise_for_status()  # Raises HTTPError for bad status codes
                    logger.info(f"Successfully accessed verification link: {response.status_code}")
                    client.mark_as_read(msg["id"])
                except requests.exceptions.Timeout:
                    logger.error("Request timed out")
                except requests.exceptions.HTTPError as e:
                    logger.error(f"HTTP error: {e.response.status_code}")
                except requests.exceptions.RequestException as e:
                    logger.error(f"Request failed: {e}")

                return


if __name__ == "__main__":
    # Run with: python main.py (production - nothing prints)
    # Run with: python main.py --info (info + warnings + errors)
    # Run with: python main.py --debug (everything)
    import sys

    debug = "--debug" in sys.argv
    info = "--info" in sys.argv
    main(debug=debug, info=info)
