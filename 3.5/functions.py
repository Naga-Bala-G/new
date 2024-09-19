import logging
import psycopg2
import requests
from config import CLIENT_ID, CLIENT_SECRET,KEYCLOAK_SERVER_URL,REALM_NAME
TOKEN_URL = f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token'

def get_db_connection():
    """Connect to the PostgreSQL database."""
    conn = psycopg2.connect(
        dbname='sso_db',
        user='postgreshackuser01',  # Replace with your DB user
        password='hackathonsrv01@',  # Replace with your DB password
        host='hackathon-postgres-01.postgres.database.azure.com',
        port='5432'
    )
    return conn


def get_admin_token():
    """Obtain an admin access token from Keycloak."""
    try:
        logging.info("Getting admin access token from Keycloak")
        response = requests.post(TOKEN_URL, data={
            'grant_type': 'client_credentials',
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
        })
        response.raise_for_status()
        logging.info("Successfully obtained admin token")
        return response.json()['access_token']
    except requests.RequestException as e:
        logging.error(f"Failed to obtain admin token: {str(e)}")
        raise