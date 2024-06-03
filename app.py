import urllib

from flask import Flask, request, jsonify
import boto3
import os
import requests
from dotenv import load_dotenv
import jwt
from jwt import PyJWKClient
import logging
import random

load_dotenv()

app = Flask(__name__)

# Load environment variables
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
COGNITO_DOMAIN = os.getenv('COGNITO_DOMAIN')
COGNITO_REGION = os.getenv('AWS_REGION')
S3_BUCKET = os.getenv('S3_BUCKET')
DYNAMO_DB_TABLE = os.getenv('DYNAMO_DB_TABLE')
JWKS_URL = os.getenv('JWKS_URL')
# Initialize AWS resources
dynamodb = boto3.resource('dynamodb', region_name=COGNITO_REGION)
employee_table = dynamodb.Table(DYNAMO_DB_TABLE)
s3 = boto3.client('s3', region_name=COGNITO_REGION)

# JWKS URL
jwks_url = f'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_5jmADyS4E/.well-known/jwks.json'
logging.debug(f"JWKS URL: {jwks_url}")
jwks_client = PyJWKClient(jwks_url)


# Authorization Service to obtain token
@app.route('/peoplesuite/oauth2/token', methods=['POST'])
def get_token():
    token_url = f'https://{COGNITO_DOMAIN}.auth.{COGNITO_REGION}.amazoncognito.com/oauth2/token'
    data = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(token_url, data=data, headers=headers)
    if response.status_code == 200:
        access_token = response.json().get('access_token')
        return jsonify({'access_token': access_token}), 200
    else:
        logging.error(f"Failed to obtain access token: {response.text}")
        return jsonify({'error': 'Failed to obtain access token'}), response.status_code


# Middleware to check the token
@app.before_request
def verify_token():
    if request.endpoint == 'get_token':
        return None

    token = request.headers.get('Authorization')
    if not token:
        logging.error("Missing access token")
        return jsonify({'error': 'Missing access token'}), 401

    parts = token.split(' ')
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        logging.error("Invalid token format")
        return jsonify({'error': 'Invalid token format'}), 401

    access_token = parts[1]
    logging.debug(f"Access Token after split: {access_token}")

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(access_token)
        logging.debug(f"Signing Key: {signing_key.key}")
        data = jwt.decode(access_token, signing_key.key, algorithms=["RS256"])
        logging.debug(f"Token data: {data}")
        request.user = data
    except urllib.error.HTTPError as e:
        logging.error(f"HTTPError: {e.code}, {e.reason}")
        return jsonify({'error': 'Failed to fetch JWKS'}), e.code
    except jwt.ExpiredSignatureError:
        logging.error('Expired token')
        return jsonify({'error': 'Expired token'}), 401
    except jwt.InvalidTokenError as e:
        logging.error(f'Invalid token: {e}')
        return jsonify({'error': 'Invalid token'}), 401


def generate_unique_employee_id():
    while True:
        employee_id = str(random.randint(1000000, 9999999))
        response = employee_table.get_item(Key={'EmployeeID': employee_id})
        if 'Item' not in response:
            return employee_id


# Employee Profile Endpoints
@app.route('/peoplesuite/apis/employees/profile', methods=['POST'])
def create_profile():
    data = request.json
    employee_id = generate_unique_employee_id()
    logging.info(f"Generated Employee ID: {employee_id}")

    employee_table.put_item(Item={
        'EmployeeID': employee_id,
        'FirstName': data['first_name'],
        'LastName': data['last_name'],
        'StartDate': data['start_date'],
        'Country': data['country']
    })
    return jsonify({'message': 'Profile created', 'EmployeeID': employee_id}), 201


@app.route('/peoplesuite/apis/employees/<employee_id>/profile', methods=['GET'])
def get_profile(employee_id):
    try:
        response = employee_table.get_item(Key={'EmployeeID': employee_id})
        if 'Item' in response:
            return jsonify(response['Item']), 200
        else:
            return jsonify({'error': 'Employee not found'}), 404
    except Exception as e:
        logging.error(f"Error fetching profile: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500


# Employee Photo Endpoints
@app.route('/peoplesuite/apis/employees/<employee_id>/photo', methods=['GET', 'POST'])
def photo(employee_id):
    if request.method == 'POST':
        file = request.files['photo']
        print("File:", file)
        # Upload the photo to S3 with the key '<employee_id>.jpg'
        s3.upload_fileobj(file, S3_BUCKET, f'{employee_id}.jpg')
        return jsonify({'message': 'Photo uploaded'}), 201
    else:
        # Generate a pre-signed URL to retrieve the photo
        photo_url = s3.generate_presigned_url('get_object', Params={
            'Bucket': S3_BUCKET,
            'Key': f'{employee_id}.jpg'
        })
        return jsonify({'photo_url': photo_url}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
