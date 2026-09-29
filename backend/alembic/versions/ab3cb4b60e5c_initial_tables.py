from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'ab3cb4b60e5c'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('ml_model_registry',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('model_name', sa.String(length=100), nullable=False),
        sa.Column('model_version', sa.String(length=50), nullable=False),
        sa.Column('file_path', sa.String(length=500), nullable=False),
        sa.Column('accuracy', sa.Float(), nullable=False),
        sa.Column('f1_score', sa.Float(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('trained_samples_count', sa.Integer(), nullable=False),
        sa.Column('hyperparameters', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ml_model_registry_id'), 'ml_model_registry', ['id'], unique=False)
    op.create_index(op.f('ix_ml_model_registry_model_name'), 'ml_model_registry', ['model_name'], unique=False)
    op.create_table('policy_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=500), nullable=False),
        sa.Column('scope', sa.String(length=50), nullable=False),
        sa.Column('condition_expression', sa.JSON(), nullable=False),
        sa.Column('priority', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_policy_rules_id'), 'policy_rules', ['id'], unique=False)
    op.create_table('users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=True),
        sa.Column('full_name', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('is_google_user', sa.Boolean(), nullable=False),
        sa.Column('google_id', sa.String(length=255), nullable=True),
        sa.Column('google_access_token', sa.Text(), nullable=True),
        sa.Column('google_refresh_token', sa.Text(), nullable=True),
        sa.Column('avatar_url', sa.String(length=500), nullable=True),
        sa.Column('organization_name', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('last_login_at', sa.DateTime(), nullable=True),
        sa.Column('last_login_ip', sa.String(length=100), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_google_id'), 'users', ['google_id'], unique=True)
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_table('audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('entity_type', sa.String(length=100), nullable=False),
        sa.Column('entity_id', sa.String(length=100), nullable=True),
        sa.Column('ip_address', sa.String(length=100), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'], unique=False)
    op.create_index(op.f('ix_audit_logs_id'), 'audit_logs', ['id'], unique=False)
    op.create_index(op.f('ix_audit_logs_user_id'), 'audit_logs', ['user_id'], unique=False)
    op.create_table('emails',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('sender', sa.String(length=255), nullable=False),
        sa.Column('recipient', sa.String(length=255), nullable=False),
        sa.Column('subject', sa.String(length=500), nullable=False),
        sa.Column('body_plain', sa.Text(), nullable=False),
        sa.Column('body_html', sa.Text(), nullable=False),
        sa.Column('raw_mime_path', sa.String(length=500), nullable=True),
        sa.Column('message_id', sa.String(length=255), nullable=True),
        sa.Column('gmail_message_id', sa.String(length=255), nullable=True),
        sa.Column('direction', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('isolation_status', sa.String(length=50), nullable=False),
        sa.Column('spam_score', sa.Float(), nullable=False),
        sa.Column('phishing_score', sa.Float(), nullable=False),
        sa.Column('threat_verdict', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_emails_gmail_message_id'), 'emails', ['gmail_message_id'], unique=True)
    op.create_index(op.f('ix_emails_id'), 'emails', ['id'], unique=False)
    op.create_index(op.f('ix_emails_message_id'), 'emails', ['message_id'], unique=False)
    op.create_index(op.f('ix_emails_recipient'), 'emails', ['recipient'], unique=False)
    op.create_index(op.f('ix_emails_sender'), 'emails', ['sender'], unique=False)
    op.create_index(op.f('ix_emails_user_id'), 'emails', ['user_id'], unique=False)
    op.create_table('employee_prevention_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('rule_type', sa.String(length=50), nullable=False),
        sa.Column('pattern', sa.String(length=255), nullable=False),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('hits_count', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_employee_prevention_rules_id'), 'employee_prevention_rules', ['id'], unique=False)
    op.create_index(op.f('ix_employee_prevention_rules_user_id'), 'employee_prevention_rules', ['user_id'], unique=False)
    op.create_table('notifications',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('notification_type', sa.String(length=50), nullable=False),
        sa.Column('is_read', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_notifications_id'), 'notifications', ['id'], unique=False)
    op.create_index(op.f('ix_notifications_user_id'), 'notifications', ['user_id'], unique=False)
    op.create_table('user_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('session_token', sa.String(length=255), nullable=False),
        sa.Column('ip_address', sa.String(length=100), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('last_activity', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_sessions_id'), 'user_sessions', ['id'], unique=False)
    op.create_index(op.f('ix_user_sessions_session_token'), 'user_sessions', ['session_token'], unique=True)
    op.create_index(op.f('ix_user_sessions_user_id'), 'user_sessions', ['user_id'], unique=False)
    op.create_table('analyst_feedbacks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('original_verdict', sa.String(length=50), nullable=False),
        sa.Column('corrected_verdict', sa.String(length=50), nullable=False),
        sa.Column('feedback_type', sa.String(length=50), nullable=False),
        sa.Column('comments', sa.Text(), nullable=False),
        sa.Column('is_used_for_retraining', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_analyst_feedbacks_email_id'), 'analyst_feedbacks', ['email_id'], unique=False)
    op.create_index(op.f('ix_analyst_feedbacks_id'), 'analyst_feedbacks', ['id'], unique=False)
    op.create_index(op.f('ix_analyst_feedbacks_user_id'), 'analyst_feedbacks', ['user_id'], unique=False)
    op.create_table('attachments',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=False),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.Column('content_type', sa.String(length=100), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False),
        sa.Column('storage_path', sa.String(length=500), nullable=False),
        sa.Column('md5_hash', sa.String(length=64), nullable=True),
        sa.Column('sha256_hash', sa.String(length=64), nullable=True),
        sa.Column('is_malicious', sa.Boolean(), nullable=False),
        sa.Column('sandbox_verdict', sa.String(length=50), nullable=False),
        sa.Column('scan_details', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_attachments_email_id'), 'attachments', ['email_id'], unique=False)
    op.create_index(op.f('ix_attachments_id'), 'attachments', ['id'], unique=False)
    op.create_table('dlp_incidents',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('pattern_type', sa.String(length=50), nullable=False),
        sa.Column('matches_count', sa.Integer(), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('masked_sample', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_dlp_incidents_email_id'), 'dlp_incidents', ['email_id'], unique=False)
    op.create_index(op.f('ix_dlp_incidents_id'), 'dlp_incidents', ['id'], unique=False)
    op.create_index(op.f('ix_dlp_incidents_user_id'), 'dlp_incidents', ['user_id'], unique=False)
    op.create_table('quarantine_records',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('reason', sa.String(length=255), nullable=False),
        sa.Column('isolation_level', sa.String(length=50), nullable=False),
        sa.Column('is_released', sa.Boolean(), nullable=False),
        sa.Column('released_by_user_id', sa.Integer(), nullable=True),
        sa.Column('released_at', sa.DateTime(), nullable=True),
        sa.Column('quarantine_expires_at', sa.DateTime(), nullable=True),
        sa.Column('action_history', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['released_by_user_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email_id')
    )
    op.create_index(op.f('ix_quarantine_records_id'), 'quarantine_records', ['id'], unique=False)
    op.create_index(op.f('ix_quarantine_records_user_id'), 'quarantine_records', ['user_id'], unique=False)
    op.create_table('remediation_tasks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=True),
        sa.Column('action_type', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('triggered_by_user_id', sa.Integer(), nullable=True),
        sa.Column('result_summary', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['triggered_by_user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_remediation_tasks_id'), 'remediation_tasks', ['id'], unique=False)
    op.create_table('scan_results',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=False),
        sa.Column('spf_status', sa.String(length=50), nullable=False),
        sa.Column('dkim_status', sa.String(length=50), nullable=False),
        sa.Column('dmarc_status', sa.String(length=50), nullable=False),
        sa.Column('nlp_score', sa.Float(), nullable=False),
        sa.Column('dlp_hits', sa.JSON(), nullable=False),
        sa.Column('ocr_extracted_text', sa.Text(), nullable=False),
        sa.Column('sandbox_details', sa.JSON(), nullable=False),
        sa.Column('ml_spam_probability', sa.Float(), nullable=False),
        sa.Column('ml_phishing_probability', sa.Float(), nullable=False),
        sa.Column('final_verdict', sa.String(length=50), nullable=False),
        sa.Column('scanned_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email_id')
    )
    op.create_index(op.f('ix_scan_results_id'), 'scan_results', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_scan_results_id'), table_name='scan_results')
    op.drop_table('scan_results')
    op.drop_index(op.f('ix_remediation_tasks_id'), table_name='remediation_tasks')
    op.drop_table('remediation_tasks')
    op.drop_index(op.f('ix_quarantine_records_user_id'), table_name='quarantine_records')
    op.drop_index(op.f('ix_quarantine_records_id'), table_name='quarantine_records')
    op.drop_table('quarantine_records')
    op.drop_index(op.f('ix_dlp_incidents_user_id'), table_name='dlp_incidents')
    op.drop_index(op.f('ix_dlp_incidents_id'), table_name='dlp_incidents')
    op.drop_index(op.f('ix_dlp_incidents_email_id'), table_name='dlp_incidents')
    op.drop_table('dlp_incidents')
    op.drop_index(op.f('ix_attachments_id'), table_name='attachments')
    op.drop_index(op.f('ix_attachments_email_id'), table_name='attachments')
    op.drop_table('attachments')
    op.drop_index(op.f('ix_analyst_feedbacks_user_id'), table_name='analyst_feedbacks')
    op.drop_index(op.f('ix_analyst_feedbacks_id'), table_name='analyst_feedbacks')
    op.drop_index(op.f('ix_analyst_feedbacks_email_id'), table_name='analyst_feedbacks')
    op.drop_table('analyst_feedbacks')
    op.drop_index(op.f('ix_user_sessions_user_id'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_session_token'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_id'), table_name='user_sessions')
    op.drop_table('user_sessions')
    op.drop_index(op.f('ix_notifications_user_id'), table_name='notifications')
    op.drop_index(op.f('ix_notifications_id'), table_name='notifications')
    op.drop_table('notifications')
    op.drop_index(op.f('ix_employee_prevention_rules_user_id'), table_name='employee_prevention_rules')
    op.drop_index(op.f('ix_employee_prevention_rules_id'), table_name='employee_prevention_rules')
    op.drop_table('employee_prevention_rules')
    op.drop_index(op.f('ix_emails_user_id'), table_name='emails')
    op.drop_index(op.f('ix_emails_sender'), table_name='emails')
    op.drop_index(op.f('ix_emails_recipient'), table_name='emails')
    op.drop_index(op.f('ix_emails_message_id'), table_name='emails')
    op.drop_index(op.f('ix_emails_id'), table_name='emails')
    op.drop_index(op.f('ix_emails_gmail_message_id'), table_name='emails')
    op.drop_table('emails')
    op.drop_index(op.f('ix_audit_logs_user_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_action'), table_name='audit_logs')
    op.drop_table('audit_logs')
    op.drop_index(op.f('ix_users_id'), table_name='users')
    op.drop_index(op.f('ix_users_google_id'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
    op.drop_index(op.f('ix_policy_rules_id'), table_name='policy_rules')
    op.drop_table('policy_rules')
    op.drop_index(op.f('ix_ml_model_registry_model_name'), table_name='ml_model_registry')
    op.drop_index(op.f('ix_ml_model_registry_id'), table_name='ml_model_registry')
    op.drop_table('ml_model_registry')
