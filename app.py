import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from models import db, User, AnalysisResult
from mapreduce import run_mapreduce
import tempfile
from sqlalchemy import text, inspect

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-prod')
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    DATABASE_URL = 'sqlite:///test.db'
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------- DIALECT DETECTION -------------------
def is_sqlite():
    """Return True if the database is SQLite (for local testing)."""
    return DATABASE_URL.startswith('sqlite')

# ------------------- MIGRATION HELPERS (add missing columns) -------------------
def column_exists(table_name, column_name):
    inspector = inspect(db.engine)
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns

def add_column_if_missing(table_name, column_name, column_type, default_value=None):
    if not column_exists(table_name, column_name):
        with db.engine.connect() as conn:
            conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))
            conn.commit()
        print(f"Added column '{column_name}' to table '{table_name}'.")
        if default_value is not None:
            with db.engine.connect() as conn:
                conn.execute(text(f"UPDATE {table_name} SET {column_name} = {default_value} WHERE {column_name} IS NULL"))
                conn.commit()
            print(f"Set default value for '{column_name}' to '{default_value}'.")

def add_foreign_key_if_missing():
    """Add user_id column to analysis_result, but skip FOREIGN KEY for SQLite."""
    # First, add the column if it doesn't exist
    if not column_exists('analysis_result', 'user_id'):
        add_column_if_missing('analysis_result', 'user_id', 'INTEGER')
    
    # Only add the FOREIGN KEY constraint for PostgreSQL (not SQLite)
    if not is_sqlite():
        # Check if constraint already exists (simple check: try to add it)
        with db.engine.connect() as conn:
            try:
                conn.execute(text("ALTER TABLE analysis_result ADD CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES user(id)"))
                conn.commit()
                print("Added foreign key constraint fk_user_id.")
            except Exception as e:
                print(f"Foreign key constraint probably already exists: {e}")

# ------------------- DB INIT & MIGRATIONS -------------------
with app.app_context():
    # Create all tables (if they don't exist)
    db.create_all()

    # 1. Add 'role' column to 'user' if missing
    if not column_exists('user', 'role'):
        add_column_if_missing('user', 'role', 'VARCHAR(20)', "'user'")
        print("Added 'role' column to 'user' table with default 'user'.")

    # 2. Add 'user_id' to 'analysis_result' if missing (and handle foreign key)
    add_foreign_key_if_missing()

    # Ensure admin user exists with role='admin'
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
        print(f"Admin '{admin_username}' created with role 'admin'.")
    else:
        # If admin exists but role is not 'admin', update it
        if admin.role != 'admin':
            admin.role = 'admin'
            db.session.commit()
            print(f"Updated admin '{admin_username}' role to 'admin'.")

# ------------------- ROUTES (unchanged) -------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
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
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'logfile' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['logfile']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if not file.filename.endswith('.log'):
            flash('Only .log files are allowed')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as tmp:
                file.save(tmp.name)
                tmp_path = tmp.name
            error_counts, hour_counts = run_mapreduce(tmp_path)
            result = AnalysisResult(
                filename=filename,
                error_counts=error_counts,
                hour_counts=hour_counts,
                user_id=current_user.id
            )
            db.session.add(result)
            db.session.commit()
            flash('File processed successfully!')
            return redirect(url_for('view_result', result_id=result.id))
        except Exception as e:
            flash(f'Processing failed: {str(e)}')
            return redirect(request.url)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
    return render_template('upload.html')

@app.route('/result/<int:result_id>')
@login_required
def view_result(result_id):
    result = AnalysisResult.query.get_or_404(result_id)
    if current_user.role != 'admin' and result.user_id != current_user.id:
        abort(403)
    return render_template('dashboard.html', result=result)

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        abort(403)
    all_results = AnalysisResult.query.order_by(AnalysisResult.uploaded_at.desc()).all()
    users = User.query.all()
    return render_template('admin_dashboard.html', results=all_results, users=users)

@app.route('/user')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        return redirect(url_for('admin_dashboard'))
    my_results = AnalysisResult.query.filter_by(user_id=current_user.id).order_by(AnalysisResult.uploaded_at.desc()).all()
    return render_template('user_dashboard.html', results=my_results)

@app.route('/history')
@login_required
def history():
    if current_user.role == 'admin':
        results = AnalysisResult.query.order_by(AnalysisResult.uploaded_at.desc()).all()
    else:
        results = AnalysisResult.query.filter_by(user_id=current_user.id).order_by(AnalysisResult.uploaded_at.desc()).all()
    return render_template('history.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)