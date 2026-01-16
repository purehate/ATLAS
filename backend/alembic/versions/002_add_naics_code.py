"""Add NAICS code to industries

Revision ID: 002_add_naics_code
Revises: 001_initial_migration
Create Date: 2026-01-16

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '002_add_naics_code'
down_revision = '001_initial'
branch_labels = None
depends_on = None


def upgrade():
    # Add naics_code column to industries table
    op.add_column('industries', sa.Column('naics_code', sa.String(50), nullable=True))
    op.create_index('ix_industries_naics_code', 'industries', ['naics_code'])


def downgrade():
    op.drop_index('ix_industries_naics_code', table_name='industries')
    op.drop_column('industries', 'naics_code')
