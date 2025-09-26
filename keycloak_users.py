#!/usr/bin/env python3

import os
import re
import sys
import time
import json
import logging
from datetime import datetime
from urllib.parse import urljoin

import jwt
import requests


NAME = os.path.basename(sys.argv[0])
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
KEYCLOAK_TOKEN_URI = os.getenv("KEYCLOAK_TOKEN_URI")
KEYCLOAK_API_BASE_URI = os.getenv("KEYCLOAK_API_BASE_URI")
KEYCLOAK_PAGE_SIZE = int(os.getenv("KEYCLOAK_PAGE_SIZE", 10))
KEYCLOAK_VERIFICATION_PERIOD = int(os.getenv("KEYCLOAK_VERIFICATION_PERIOD", 15*60)) # 15 minutes


logger = logging.getLogger(NAME)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


def get_admin_token(token=None):
    if token:
        claims = jwt.decode(token, verify=False)
        if time.time() < claims["exp"]:
            return token
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials"
    }
    try:
        response = requests.post(KEYCLOAK_TOKEN_URI, data=payload)
        token = response.json()["access_token"]
    except Exception as e:
        logger.error(e)
    return token


if __name__ == "__main__":
    start_time = datetime.now()
    token = get_admin_token()
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # Users count
    users_count = 0
    try:
        endpoint = urljoin(KEYCLOAK_API_BASE_URI, "users/count?emailVerified=false")
        response = requests.get(endpoint, headers=headers)
        users_count = int(response.text)
    except Exception as e:
        logger.info(f"GET {endpoint} {response.status_code}")
        logger.info(f"{response.text}")
        logger.error(e)
    logger.info(f"Users count is {users_count}")

    # Delete users with emailVerified=false
    if users_count > 0:
        for i in range(users_count // KEYCLOAK_PAGE_SIZE + 2):
            users = []
            try:
                endpoint = urljoin(
                    KEYCLOAK_API_BASE_URI,
                    f"users?emailVerified=false&first={i*KEYCLOAK_PAGE_SIZE}&max={KEYCLOAK_PAGE_SIZE}")
                response = requests.get(endpoint, headers=headers)
                users = json.loads(response.text)
            except Exception as e:
                logger.info(f"GET {endpoint} {response.status_code}")
                logger.info(f"{response.text}")
                logger.error(e)

            for user in users:
                if not (set(["email", "firstName", "lastName"]) - set(user) or user.get("emailVerified", True)):
                    verification_period = time.time() - user["createdTimestamp"] // 1000
                    if verification_period >= KEYCLOAK_VERIFICATION_PERIOD:
                        try:
                            endpoint = urljoin(KEYCLOAK_API_BASE_URI, f"users/{user['id']}")
                            request = requests.delete(endpoint, headers=headers)
                            logger.info(f"Remove {user['id']} {user['email']} {request.status_code}")
                        except Exception as e:
                            logger.info(user)
                            logger.info(f"DELETE {endpoint} {response.status_code}")
                            logger.info(f"{response.text}")
                            logger.error(e)

    stop_time = datetime.now()
    logger.info(f"Elapsed time is {stop_time - start_time}")
