from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash


db = SQLAlchemy()


# =========================
# USER MODEL
# =========================
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationship: one user has many analysis results
    analyses = db.relationship(
        'AnalysisResult',
        backref='owner',
        lazy=True,
        cascade='all, delete-orphan'
    )
    
    # ------------------- Password Helpers -------------------
    def set_password(self, password):
        """Hash and store password securely"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password against stored hash"""
        return check_password_hash(self.password_hash, password)
    
    # ------------------- Role Helpers -------------------
    def is_admin(self):
        return self.role == 'admin'
    
    def is_regular_user(self):
        return self.role == 'user'
    
    # ------------------- Serialization -------------------
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'total_analyses': len(self.analyses)
        }
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


# =========================
# ANALYSIS RESULT MODEL
# =========================
class AnalysisResult(db.Model):
    __tablename__ = 'analysis_result'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    
    # MapReduce results (JSON)
    error_counts = db.Column(db.JSON, nullable=False, default=dict)
    hour_counts = db.Column(db.JSON, nullable=False, default=dict)
    url_counts = db.Column(db.JSON, nullable=True, default=dict)       # Phase 5
    country_counts = db.Column(db.JSON, nullable=True, default=dict)   # Phase 6
    
    # File metadata
    file_size = db.Column(db.Integer, nullable=True)          # bytes
    total_lines = db.Column(db.Integer, nullable=True)
    processing_time = db.Column(db.Float, nullable=True)      # seconds
    
    # Ownership
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    
    # ------------------- Helper Methods -------------------
    def total_errors(self):
        """Sum of all HTTP errors"""
        if not self.error_counts:
            return 0
        return sum(self.error_counts.values())
    
    def total_requests(self):
        """Sum of all hourly requests"""
        if not self.hour_counts:
            return 0
        return sum(self.hour_counts.values())
    
    def top_urls(self, limit=10):
        """Return top N most requested URLs"""
        if not self.url_counts:
            return []
        sorted_urls = sorted(self.url_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_urls[:limit]
    
    def top_errors(self, limit=5):
        """Return top N most frequent errors"""
        if not self.error_counts:
            return []
        sorted_errors = sorted(self.error_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_errors[:limit]
    
    def busiest_hours(self, limit=5):
        """Return top N busiest hours"""
        if not self.hour_counts:
            return []
        sorted_hours = sorted(self.hour_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_hours[:limit]
    
    def error_rate(self):
        """Calculate error percentage"""
        total_req = self.total_requests()
        if total_req == 0:
            return 0.0
        return round((self.total_errors() / total_req) * 100, 2)
    
    def get_user(self):
        """Get the owner of this analysis"""
        return self.owner
    
    # ------------------- Serialization -------------------
    def to_dict(self, include_data=True):
        base = {
            'id': self.id,
            'filename': self.filename,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'user_id': self.user_id,
            'total_errors': self.total_errors(),
            'total_requests': self.total_requests(),
            'error_rate': self.error_rate(),
            'processing_time': self.processing_time,
            'file_size': self.file_size,
            'total_lines': self.total_lines
        }
        if include_data:
            base.update({
                'error_counts': self.error_counts,
                'hour_counts': self.hour_counts,
                'url_counts': self.url_counts,
                'country_counts': self.country_counts
            })
        return base
    
    def __repr__(self):
        return f'<AnalysisResult {self.filename} (user_id={self.user_id})>'