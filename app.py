from flask import Flask, request, jsonify, abort, render_template
import requests

app = Flask(__name__)

# Keycloak configuration
KEYCLOAK_SERVER_URL = 'http://localhost:8080'
REALM_NAME = 'myrealm'
CLIENT_ID = 'myclient'
CLIENT_SECRET = 'PIzlbexHnpy7rgxcnHtVb9dgXu0Ca4mo'
REDIRECT_URI = 'http://localhost:5000/callback'
TOKEN_URL = f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token'
USERS_URL = f'{KEYCLOAK_SERVER_URL}/admin/realms/{REALM_NAME}/users'

def get_admin_token():
    # Get the admin access token from Keycloak
    response = requests.post(TOKEN_URL, data={
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    })
    response.raise_for_status()
    return response.json()['access_token']

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/dashboard/executive')
def executive_dashboard():
    return render_template('dashboard_executive.html')

@app.route('/dashboard/manager')
def manager_dashboard():
    return render_template('dashboard_manager.html')

@app.route('/dashboard/employee')
def employee_dashboard():
    return render_template('dashboard_employee.html')

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        abort(400, description='Missing parameters')

    # Obtain access token
    token_response = requests.post(f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token', data={
        'grant_type': 'password',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'username': username,
        'password': password,
    })

    if token_response.status_code != 200:
        abort(token_response.status_code, description='Authentication failed')

    token_data = token_response.json()

    # Introspect the access token to get user roles
    introspect_response = requests.post(f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token/introspect', data={
        'token': token_data['access_token'],
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    })

    if introspect_response.status_code != 200:
        abort(introspect_response.status_code, description='Token introspection failed')

    introspect_data = introspect_response.json()

    if not introspect_data.get('active'):
        abort(401, description='Token is not active or invalid')

    # Extract roles from the token
    resource_access = introspect_data.get('resource_access', {})
    user_roles = resource_access.get('myclient', {}).get('roles', [])

    # Return token data and user roles
    return jsonify({
        'access_token': token_data['access_token'],
        'refresh_token': token_data['refresh_token'],
        'roles': user_roles
    })

@app.route('/api/auth/user-details', methods=['POST'])
def user_details():
    # Extract the access token from the Authorization header
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        abort(400, description='Authorization header is missing')
    
    # Parse the access token from the header
    token_prefix = 'Bearer '
    if not auth_header.startswith(token_prefix):
        abort(400, description='Invalid authorization header format')
    
    access_token = auth_header[len(token_prefix):]
    
    if not access_token:
        abort(400, description='Missing access token')

    # Introspect the access token
    introspect_response = requests.post(f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token/introspect', data={
        'token': access_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    })

    if introspect_response.status_code != 200:
        abort(introspect_response.status_code, description='Token introspection failed')

    introspect_data = introspect_response.json()
    
    # Check if token is active
    if not introspect_data.get('active'):
        abort(401, description='Token is not active or invalid')

    # Return user details
    return jsonify(introspect_data)

@app.route('/api/auth/role-check', methods=['POST'])
def role_check():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        abort(400, description='Authorization header is missing')
    
    token_prefix = 'Bearer '
    if not auth_header.startswith(token_prefix):
        abort(400, description='Invalid authorization header format')
    
    access_token = auth_header[len(token_prefix):]
    
    if not access_token:
        abort(400, description='Missing access token')

    # Introspect the access token
    introspect_response = requests.post(f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token/introspect', data={
        'token': access_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    })

    if introspect_response.status_code != 200:
        abort(introspect_response.status_code, description='Token introspection failed')

    introspect_data = introspect_response.json()
    
    if not introspect_data.get('active'):
        abort(401, description='Token is not active or invalid')
    
    # Check for roles in resource_access
    resource_access = introspect_data.get('resource_access', {})
    
    # Extract roles for 'myclient'
    user_roles = resource_access.get('myclient', {}).get('roles', [])
    
    # Determine user role
    if 'executive' in user_roles:
        return jsonify({'message': 'executive'})
    elif 'Manager' in user_roles:
        return jsonify({'message': 'Manager'})
    elif 'Employee' in user_roles:
        return jsonify({'message': 'Employee'})
    else:
        return jsonify({'message': 'Unknown'})

@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    data = request.json
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        abort(400, description='Missing refresh token')

    # Request a new access token using the refresh token
    token_response = requests.post(f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token', data={
        'grant_type': 'refresh_token',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'refresh_token': refresh_token,
    })

    if token_response.status_code != 200:
        abort(token_response.status_code, description='Token refresh failed')

    token_data = token_response.json()

    # Return new token data
    return jsonify(token_data)

@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        # Get the admin access token to fetch user data
        access_token = get_admin_token()
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Fetch the list of users
        response = requests.get(USERS_URL, headers=headers)
        response.raise_for_status()
        users = response.json()

        # Fetch additional user details
        user_details = []
        for user in users:
            user_id = user.get('id')
            if user_id:
                user_detail_url = f'{USERS_URL}/{user_id}'
                user_response = requests.get(user_detail_url, headers=headers)
                if user_response.status_code == 200:
                    user_detail = user_response.json()
                    user_details.append(user_detail)
                else:
                    user_details.append({'id': user_id, 'error': 'Failed to fetch user details'})
            else:
                user_details.append({'error': 'User ID missing'})

        return jsonify(user_details)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
