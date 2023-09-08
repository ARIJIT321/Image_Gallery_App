from flask import Flask, request, jsonify, send_from_directory, render_template,redirect,url_for,session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import datetime
import os
from werkzeug.utils import secure_filename
from functools import wraps
from flask_oauthlib.client import OAuth
# import viewer

app = Flask(__name__)

# Secret key for JWT (replace with your own secret)
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Google OAuth configuration
app.config['GOOGLE_ID'] = 'your_google_client_id'
app.config['GOOGLE_SECRET'] = 'your_google_client_secret'


# Viewer.js configuration
app.config['VIEWER_JS'] = True


# Create a Limiter instance with rate limiting
# limiter = Limiter(
#     app,
#     key_func=get_remote_address,
#     default_limits=["5 per minute"]
# )

# Function to generate a JWT token
def generate_token():
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
    payload = {
        'exp': expiration,
        'iat': datetime.datetime.utcnow(),
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token


# OAuth setup
oauth = OAuth(app)


google = oauth.remote_app(
    'google',
    consumer_key=app.config.get('GOOGLE_ID'),
    consumer_secret=app.config.get('GOOGLE_SECRET'),
    request_token_params={
        'scope': 'email',
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        return f(*args, **kwargs)

    return decorated



# Set the path to the folder where images will be uploaded
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Create the "uploads" directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


# Route to upload an image (Part 1)
@app.route('/upload', methods=['POST'])
# @limiter.limit("5 per minute")  # Rate limiting for this route
@token_required
def upload_image():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'message': 'File uploaded successfully', 'filename': filename})


# Google OAuth login route
@app.route('/login')
def login():
    return google.authorize(callback=url_for('authorized', _external=True))

# Google OAuth authorized callback
@app.route('/login/authorized')
def authorized():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (response['access_token'], '')
    user_info = google.get('userinfo')
    # You can store or use the user_info as needed.
    return 'Logged in as: ' + user_info.data['email']

# Google OAuth logout route
@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))


# Route to get the uploaded image by filename (Part 1)
@app.route('/uploads/<filename>')
def get_uploaded_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/view/<filename>')
def view_image(filename):
    return render_template('image.html', filename=filename)

@app.route('/all_images')
def all_images():
    images = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('all_images.html', images=images)

if __name__ == '__main__':
    app.run()
