import os
import time
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from models import db, User, AnalysisResult
from mapreduce import run_mapreduce
import tempfile
from sqlalchemy import text, inspect

# SocketIO for real-time
try:
    from flask_socketio import SocketIO, emit
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False
    print("⚠️ Flask-SocketIO not installed. Real-time features disabled.")

# Anomaly detection (optional)
try:
    from anomaly import detect_anomalies, get_anomaly_summary
    ANOMALY_AVAILABLE = True
except ImportError:
    ANOMALY_AVAILABLE = False
    print("⚠️ anomaly.py not found. Anomaly detection disabled.")

# Alerts (optional)
try:
    from alerts import check_and_alert
    ALERTS_AVAILABLE = True
except ImportError:
    ALERTS_AVAILABLE = False
    print("⚠️ alerts.py not found. Alerts disabled.")


load_dotenv()

app = Flask(__name__)

# =========================
# CONFIGURATION
# =========================
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-prod')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB max file size
app.config['UPLOAD_EXTENSIONS'] = ['.log', '.txt', '.json', '.out']

DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    DATABASE_URL = 'sqlite:///test.db'
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

db.init_app(app)

# SocketIO initialization
if SOCKETIO_AVAILABLE:
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
else:
    socketio = None

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# =========================
# HELPERS
# =========================
def is_sqlite():
    return DATABASE_URL.startswith('sqlite')


def allowed_file(filename):
    """Check if file extension is allowed"""
    return any(
        filename.lower().endswith(ext)
        for ext in app.config['UPLOAD_EXTENSIONS']
    )


def validate_credentials(username, password):
    """Validate username and password strength"""
    if not username or len(username) < 3 or len(username) > 50:
        return False, "Username must be 3-50 characters"
    if not username.isalnum() and '_' not in username:
        return False, "Username can only contain letters, numbers, and underscores"
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters"
    if len(password) > 100:
        return False, "Password too long"
    return True, None


# =========================
# MIGRATION HELPERS
# =========================
def column_exists(table_name, column_name):
    inspector = inspect(db.engine)
    try:
        columns = [col['name'] for col in inspector.get_columns(table_name)]
        return column_name in columns
    except Exception:
        return False


def add_column_if_missing(table_name, column_name, column_type, default_value=None):
    if not column_exists(table_name, column_name):
        with db.engine.connect() as conn:
            conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))
            conn.commit()
        print(f"✅ Added column '{column_name}' to '{table_name}'.")
        if default_value is not None:
            with db.engine.connect() as conn:
                conn.execute(text(f"UPDATE {table_name} SET {column_name} = {default_value} WHERE {column_name} IS NULL"))
                conn.commit()


def add_foreign_key_if_missing():
    if not column_exists('analysis_result', 'user_id'):
        add_column_if_missing('analysis_result', 'user_id', 'INTEGER')
    if not is_sqlite():
        with db.engine.connect() as conn:
            try:
                conn.execute(text('ALTER TABLE analysis_result ADD CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES "user"(id)'))
                conn.commit()
                print("✅ Foreign key constraint added.")
            except Exception:
                pass


# =========================
# DB INIT
# =========================
with app.app_context():
    db.create_all()

    if not column_exists('user', 'role'):
        add_column_if_missing('user', 'role', 'VARCHAR(20)', "'user'")

    add_foreign_key_if_missing()

    # Real-world feature columns
    new_columns = [
        ('analysis_result', 'url_counts', 'JSON', 'NULL'),
        ('analysis_result', 'country_counts', 'JSON', 'NULL'),
        ('analysis_result', 'file_size', 'INTEGER', 'NULL'),
        ('analysis_result', 'total_lines', 'INTEGER', 'NULL'),
        ('analysis_result', 'processing_time', 'FLOAT', 'NULL'),
    ]
    for table, col, col_type, default in new_columns:
        if not column_exists(table, col):
            add_column_if_missing(table, col, col_type, default)

    # Create admin
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
    admin = User.query.filter_by(username=admin_username).first()
    if not admin:
        admin = User(
            username=admin_username,
            password_hash=generate_password_hash(admin_password),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()
        print(f"✅ Admin '{admin_username}' created.")
    elif admin.role != 'admin':
        admin.role = 'admin'
        db.session.commit()

    print(f"✅ Database initialized ({'SQLite' if is_sqlite() else 'PostgreSQL'})")


# =========================
# ROUTES
# =========================
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        
        flash('Invalid credentials')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validate
        is_valid, error = validate_credentials(username, password)
        if not is_valid:
            flash(error)
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken.')
            return redirect(url_for('register'))
        
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            role='user'
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('login'))


# =========================
# UPLOAD
# =========================
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        # Check file part
        if 'logfile' not in request.files:
            flash('No file part in request')
            return redirect(request.url)
        
        file = request.files['logfile']
        
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        if not allowed_file(file.filename):
            flash(f'Allowed formats: {", ".join(app.config["UPLOAD_EXTENSIONS"])}')
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        tmp_path = None
        start_time = time.time()
        
        try:
            # Save to temp
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as tmp:
                file.save(tmp.name)
                tmp_path = tmp.name
            
            file_size = os.path.getsize(tmp_path)
            
            # Count lines
            with open(tmp_path, 'r', encoding='utf-8', errors='ignore') as f:
                total_lines = sum(1 for _ in f)
            
            # Run MapReduce
            result_data = run_mapreduce(tmp_path)
            
            # Handle 2, 3, or 4 values
            if len(result_data) == 4:
                error_counts, hour_counts, url_counts, country_counts = result_data
            elif len(result_data) == 3:
                error_counts, hour_counts, url_counts = result_data
                country_counts = {}
            else:
                error_counts, hour_counts = result_data
                url_counts, country_counts = {}, {}
            
            processing_time = round(time.time() - start_time, 3)
            
            # Save to DB
            result = AnalysisResult(
                filename=filename,
                error_counts=error_counts,
                hour_counts=hour_counts,
                url_counts=dict(url_counts) if url_counts else None,
                country_counts=dict(country_counts) if country_counts else None,
                file_size=file_size,
                total_lines=total_lines,
                processing_time=processing_time,
                user_id=current_user.id
            )
            db.session.add(result)
            db.session.commit()
            
            # Send alerts
            if ALERTS_AVAILABLE:
                try:
                    check_and_alert(error_counts, hour_counts, filename)
                except Exception as e:
                    print(f"Alert failed: {e}")
            
            # Real-time notification
            if socketio:
                socketio.emit('new_analysis', {
                    'filename': filename,
                    'total_errors': sum(error_counts.values()),
                    'user': current_user.username
                })
            
            flash(f'File processed in {processing_time}s ({total_lines} lines)')
            return redirect(url_for('view_result', result_id=result.id))
        
        except Exception as e:
            print(f"❌ Upload error: {e}")
            flash(f'Processing failed: {str(e)}')
            return redirect(request.url)
        
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
    
    return render_template('upload.html')


# =========================
# VIEW RESULT
# =========================
@app.route('/result/<int:result_id>')
@login_required
def view_result(result_id):
    result = AnalysisResult.query.get_or_404(result_id)
    
    # Access control
    if current_user.role != 'admin' and result.user_id != current_user.id:
        abort(403)
    
    # Anomaly detection
    anomalies = []
    anomaly_summary = {}
    if ANOMALY_AVAILABLE and result.hour_counts:
        try:
            anomalies = detect_anomalies(
                result.hour_counts,
                error_counts=result.error_counts
            )
            anomaly_summary = get_anomaly_summary(anomalies)
        except Exception as e:
            print(f"Anomaly detection failed: {e}")
    
    return render_template(
        'view_result.html',
        result=result,
        anomalies=anomalies,
        anomaly_summary=anomaly_summary
    )


# =========================
# DASHBOARDS
# =========================
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        abort(403)
    
    all_results = AnalysisResult.query.order_by(
        AnalysisResult.uploaded_at.desc()
    ).all()
    
    users = User.query.order_by(User.id).all()
    
    # Summary stats
    stats = {
        'total_users': len(users),
        'total_analyses': len(all_results),
        'total_errors': sum(r.total_errors() for r in all_results),
        'total_requests': sum(r.total_requests() for r in all_results),
    }
    
    return render_template(
        'admin_dashboard.html',
        results=all_results,
        users=users,
        stats=stats
    )


@app.route('/user')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        return redirect(url_for('admin_dashboard'))
    
    my_results = AnalysisResult.query.filter_by(
        user_id=current_user.id
    ).order_by(AnalysisResult.uploaded_at.desc()).all()
    
    stats = {
        'total_analyses': len(my_results),
        'total_errors': sum(r.total_errors() for r in my_results),
        'total_requests': sum(r.total_requests() for r in my_results),
    }
    
    return render_template(
        'user_dashboard.html',
        results=my_results,
        stats=stats
    )


@app.route('/history')
@login_required
def history():
    if current_user.role == 'admin':
        results = AnalysisResult.query.order_by(
            AnalysisResult.uploaded_at.desc()
        ).all()
    else:
        results = AnalysisResult.query.filter_by(
            user_id=current_user.id
        ).order_by(AnalysisResult.uploaded_at.desc()).all()
    
    return render_template('history.html', results=results)


# =========================
# API ENDPOINTS
# =========================
@app.route('/health')
def health():
    """Health check for Railway"""
    return jsonify({
        'status': 'ok',
        'service': 'secure-log-analyzer',
        'database': 'sqlite' if is_sqlite() else 'postgresql',
        'socketio': SOCKETIO_AVAILABLE,
        'anomaly': ANOMALY_AVAILABLE,
        'alerts': ALERTS_AVAILABLE
    }), 200


@app.route('/api/stats')
@login_required
def api_stats():
    """API: Get summary statistics"""
    if current_user.role == 'admin':
        results = AnalysisResult.query.all()
    else:
        results = AnalysisResult.query.filter_by(user_id=current_user.id).all()
    
    return jsonify({
        'total_analyses': len(results),
        'total_errors': sum(r.total_errors() for r in results),
        'total_requests': sum(r.total_requests() for r in results),
    })


@app.route('/api/result/<int:result_id>')
@login_required
def api_result(result_id):
    """API: Get analysis result as JSON"""
    result = AnalysisResult.query.get_or_404(result_id)
    if current_user.role != 'admin' and result.user_id != current_user.id:
        abort(403)
    return jsonify(result.to_dict())


# =========================
# ERROR HANDLERS
# =========================
@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(413)
def file_too_large(e):
    flash('File too large. Maximum size is 100 MB.')
    return redirect(url_for('upload'))


@app.errorhandler(500)
def server_error(e):
    db.session.rollback()
    return render_template('errors/500.html'), 500


# =========================
# SOCKETIO EVENTS
# =========================
if SOCKETIO_AVAILABLE:
    @socketio.on('connect')
    def handle_connect():
        print(f'✅ Client connected: {request.sid}')
    
    @socketio.on('disconnect')
    def handle_disconnect():
        print(f'❌ Client disconnected: {request.sid}')
    
    @socketio.on('new_log_line')
    def handle_new_log(data):
        """Process incoming log line in real-time"""
        try:
            from mapreduce import parse_log_line
            result = parse_log_line(data.get('line', ''))
            
            # Handle tuple of any length
            status = result[0] if len(result) > 0 else None
            hour = result[1] if len(result) > 1 else None
            
            if status or hour is not None:
                emit('analyzed', {
                    'status': status,
                    'hour': hour,
                    'timestamp': data.get('timestamp')
                })
        except Exception as e:
            print(f"Log line processing failed: {e}")


# =========================
# RUN APP
# =========================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'False') == 'True'
    
    print(f"\n{'='*60}")
    print(f"🚀 Starting Secure Log Analyzer")
    print(f"{'='*60}")
    print(f"📍 Port: {port}")
    print(f"🐛 Debug: {debug_mode}")
    print(f"💾 Database: {'SQLite' if is_sqlite() else 'PostgreSQL'}")
    print(f"🔌 SocketIO: {'Enabled' if SOCKETIO_AVAILABLE else 'Disabled'}")
    print(f"🔍 Anomaly: {'Enabled' if ANOMALY_AVAILABLE else 'Disabled'}")
    print(f"📢 Alerts: {'Enabled' if ALERTS_AVAILABLE else 'Disabled'}")
    print(f"{'='*60}\n")
    
    if socketio:
        socketio.run(app, host='0.0.0.0', port=port, debug=debug_mode, allow_unsafe_werkzeug=True)
    else:
        app.run(host='0.0.0.0', port=port, debug=debug_mode)