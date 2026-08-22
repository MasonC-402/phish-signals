# utils.py - Utility functions for the py-phish-signals package
# Fark Consulting LLC (https://farksecurity.com) 
# Mason Clemons

import re
import email
from email.policy import default as default_policy

def extract_urls_from_email(email_content: str) -> list[str]:
    """
    Extracts URLs from the given email content using regex patterns.

    Args:
        email_content (str): The raw content of the email.

    Returns:
        list[str]: A list of extracted URLs.
    """
    
    url_pattern_http = r'https?://[^\s]+'
    url_pattern_www = r'www\.[^\s]+'  
    url_pattern_mailto = r'mailto:[^\s]+' 
    url_pattern_ip = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'  # Matches IPv4 addresses     
    urls = re.findall(url_pattern_http, email_content) + re.findall(url_pattern_www, email_content) + re.findall(url_pattern_mailto, email_content) + re.findall(url_pattern_ip, email_content)

    return urls

def extract_headers(email_content: str) -> dict:
    """
    Extracts headers from the given email content.

    Args:
        email_content (str): The raw content of the email.

    Returns:
        dict: A dictionary containing the email headers.
    """
    parsed_email = email.message_from_string(email_content, policy=default_policy)
    return dict(parsed_email.items())

def extract_body(email_content: str) -> str:
    """
    Extracts the body from the given email content.

    Args:
        email_content (str): The raw content of the email.

    Returns:
        str: The body of the email.
    """
    parsed_email = email.message_from_string(email_content, policy=default_policy)
    if parsed_email.is_multipart():
        for part in parsed_email.iter_parts():
            if part.get_content_type() == "text/plain":
                return part.get_content()
        return ""
    else:
        return parsed_email.get_content()

def extract_subject(email_content: str) -> str:
    """
    Extracts the subject from the given email content.

    Args:
        email_content (str): The raw content of the email.

    Returns:
        str: The subject of the email.
    """
    parsed_email = email.message_from_string(email_content, policy=default_policy)
    return parsed_email.get('Subject', '')



class EmailParser:
    """
    A class to parse email content and extract relevant information such as URLs, sender, subject, etc.
    """

    def __init__(self, msg: str):
        self.msg = msg

    def parse_email(self) -> dict:
        """
        Parses the email content and extracts relevant information.

        Returns:
            dict: A dictionary containing extracted information such as URLs, sender, subject, etc.
        """
        parsed_email = email.message_from_string(self.msg, policy=default_policy)
        urls = extract_urls_from_email(self.msg)
        sender = parsed_email.get('From', '')
        subject = parsed_email.get('Subject', '')
        return {
            'urls': urls,
            'sender': sender,
            'subject': subject
        }